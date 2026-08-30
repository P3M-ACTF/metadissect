use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::net::is_loopback_host;

const SPARKLINE_SLOTS: usize = 60;
const LATENCY_CAP: usize = 512;

#[derive(Debug, Clone)]
pub struct ServeSnapshot {
    pub total: u64,
    pub ok_2xx: u64,
    pub err_4xx: u64,
    pub err_5xx: u64,
    pub rps: f64,
    pub p50_ms: u64,
    pub p99_ms: u64,
    pub last_route: String,
    pub last_status: u16,
    pub sparkline: Vec<u64>,
}

#[derive(Debug)]
pub struct ServeStats {
    total: AtomicU64,
    ok_2xx: AtomicU64,
    err_4xx: AtomicU64,
    err_5xx: AtomicU64,
    last_route: Mutex<String>,
    last_status: AtomicU16,
    latencies_ms: Mutex<VecDeque<u64>>,
    spark_buckets: Mutex<VecDeque<u64>>,
    spark_window_start: Mutex<Instant>,
}

impl ServeStats {
    pub fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            ok_2xx: AtomicU64::new(0),
            err_4xx: AtomicU64::new(0),
            err_5xx: AtomicU64::new(0),
            last_route: Mutex::new(String::new()),
            last_status: AtomicU16::new(0),
            latencies_ms: Mutex::new(VecDeque::new()),
            spark_buckets: Mutex::new(VecDeque::from(vec![0; SPARKLINE_SLOTS])),
            spark_window_start: Mutex::new(Instant::now()),
        }
    }
}

impl Default for ServeStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ServeStats {
    pub fn record(&self, route: &str, status: u16, latency: Duration) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match status {
            200..=299 => self.ok_2xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.err_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.err_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
        if let Ok(mut last) = self.last_route.lock() {
            *last = route.to_string();
        }
        self.last_status.store(status, Ordering::Relaxed);

        let ms = latency.as_millis().min(u128::from(u64::MAX)) as u64;
        if let Ok(mut lat) = self.latencies_ms.lock() {
            lat.push_back(ms);
            while lat.len() > LATENCY_CAP {
                lat.pop_front();
            }
        }

        if let (Ok(mut buckets), Ok(mut start)) =
            (self.spark_buckets.lock(), self.spark_window_start.lock())
        {
            let now = Instant::now();
            let elapsed = now.duration_since(*start);
            let slots = elapsed.as_secs() as usize;
            for _ in 0..slots {
                buckets.pop_front();
                buckets.push_back(0);
                *start += Duration::from_secs(1);
            }
            if let Some(back) = buckets.back_mut() {
                *back += 1;
            }
        }
    }

    pub fn snapshot(&self) -> ServeSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let ok_2xx = self.ok_2xx.load(Ordering::Relaxed);
        let err_4xx = self.err_4xx.load(Ordering::Relaxed);
        let err_5xx = self.err_5xx.load(Ordering::Relaxed);
        let last_status = self.last_status.load(Ordering::Relaxed);
        let last_route = self
            .last_route
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();

        let sparkline: Vec<u64> = self
            .spark_buckets
            .lock()
            .map(|b| b.iter().copied().collect())
            .unwrap_or_default();

        let rps = if sparkline.is_empty() {
            0.0
        } else {
            let sum = sparkline.iter().sum::<u64>() as f64;
            sum / sparkline.len().max(1) as f64
        };

        let (p50_ms, p99_ms) = percentile_latencies(&self.latencies_ms);

        ServeSnapshot {
            total,
            ok_2xx,
            err_4xx,
            err_5xx,
            rps,
            p50_ms,
            p99_ms,
            last_route,
            last_status,
            sparkline,
        }
    }
}

fn percentile_latencies(latencies: &Mutex<VecDeque<u64>>) -> (u64, u64) {
    let Ok(buf) = latencies.lock() else {
        return (0, 0);
    };
    if buf.is_empty() {
        return (0, 0);
    }
    let mut sorted: Vec<u64> = buf.iter().copied().collect();
    sorted.sort_unstable();
    let p50 = sorted[sorted.len() * 50 / 100];
    let p99 = sorted[sorted.len() * 99 / 100];
    (p50, p99)
}

#[derive(Clone)]
pub struct StatsLayer {
    stats: Arc<ServeStats>,
}

impl StatsLayer {
    pub fn new(stats: Arc<ServeStats>) -> Self {
        Self { stats }
    }
}

impl<S> Layer<S> for StatsLayer {
    type Service = StatsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StatsService {
            inner,
            stats: self.stats.clone(),
        }
    }
}

pub struct StatsService<S> {
    inner: S,
    stats: Arc<ServeStats>,
}

impl<S, B> Service<Request<B>> for StatsService<S>
where
    S: Service<Request<B>, Response = Response<Bytes>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    B: Send + 'static,
{
    type Response = Response<Bytes>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let stats = self.stats.clone();
        let route = req.uri().path().to_string();
        let start = Instant::now();
        Box::pin(async move {
            let res = inner.call(req).await.map_err(|e| e.into())?;
            let status = res.status().as_u16();
            stats.record(&route, status, start.elapsed());
            Ok(res)
        })
    }
}

/// Bearer or `?token=` auth for non-loopback binds. Localhost skips token check.
pub fn check_serve_token(
    host: &str,
    token: Option<&str>,
    auth_header: Option<&str>,
    query_token: Option<&str>,
) -> Result<(), StatusCode> {
    if is_loopback_host(host) {
        return Ok(());
    }
    let expected = token.filter(|t| !t.is_empty());
    if expected.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let expected = expected.unwrap();
    if auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        == Some(expected)
    {
        return Ok(());
    }
    if query_token == Some(expected) {
        return Ok(());
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Bearer auth for non-loopback binds. Prefer [`check_serve_token`] when query tokens are allowed.
pub fn check_bearer_token(
    host: &str,
    token: Option<&str>,
    auth_header: Option<&str>,
) -> Result<(), StatusCode> {
    check_serve_token(host, token, auth_header, None)
}

/// Extract `token` from a URL query string (`?token=secret&…`).
pub fn query_token_param(query: Option<&str>) -> Option<&str> {
    query.and_then(|q| {
        q.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "token" && !v.is_empty() {
                Some(v)
            } else {
                None
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_record_and_snapshot() {
        let stats = ServeStats::new();
        stats.record("/api/health", 200, Duration::from_millis(12));
        stats.record("/api/analyze", 400, Duration::from_millis(45));
        let snap = stats.snapshot();
        assert_eq!(snap.total, 2);
        assert_eq!(snap.ok_2xx, 1);
        assert_eq!(snap.err_4xx, 1);
        assert_eq!(snap.last_route, "/api/analyze");
        assert_eq!(snap.last_status, 400);
        assert!(snap.p50_ms > 0);
    }

    #[test]
    fn loopback_host_detection() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(!is_loopback_host("0.0.0.0"));
    }

    #[test]
    fn bearer_token_remote_only() {
        assert!(check_bearer_token("127.0.0.1", None, None).is_ok());
        assert!(check_bearer_token("0.0.0.0", Some("secret"), Some("Bearer secret")).is_ok());
        assert_eq!(
            check_bearer_token("0.0.0.0", Some("secret"), Some("Bearer wrong")),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn query_token_remote_only() {
        assert!(check_serve_token("127.0.0.1", None, None, Some("x")).is_ok());
        assert!(check_serve_token("0.0.0.0", Some("secret"), None, Some("secret")).is_ok());
        assert_eq!(
            check_serve_token("0.0.0.0", Some("secret"), None, Some("wrong")),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(query_token_param(Some("token=abc&x=1")), Some("abc"));
        assert_eq!(query_token_param(Some("x=1")), None);
    }
}
