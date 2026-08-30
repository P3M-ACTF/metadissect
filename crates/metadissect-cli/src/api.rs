//! Thin JSON HTTP API (no web UI). Bound to localhost by default.

use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use meta_ui::{
    check_serve_token, is_headless_env, is_tty_stdio, maybe_print_banner,
    query_token_param, shell_css, shell_css_mime,
    shell_js, shell_js_mime, Product, RetainConfig, RetainStore, ServeStats,
};
use metadissect::{
    analyze_buffer, analyze_html_string, analyze_json_string, AnalyzeOptions, Source,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "tui")]
use meta_ui::tui::{run_serve_dashboard, ServeDashboardOptions};

pub struct ServeOpts {
    pub host: String,
    pub port: u16,
    pub no_banner: bool,
    pub token: Option<String>,
    pub retain_dir: Option<std::path::PathBuf>,
    pub retain_ttl_secs: u64,
}

pub async fn serve(opts: ServeOpts) -> anyhow::Result<()> {
    maybe_print_banner(Product::Metadissect, opts.no_banner);
    meta_ui::warn_remote_bind(&opts.host);

    let token = opts
        .token
        .or_else(|| std::env::var("META_SERVE_TOKEN").ok());
    let auth = ServeAuth {
        host: opts.host.clone(),
        token,
    };
    let retain = Arc::new(RetainStore::new(
        RetainConfig::new(opts.retain_dir.unwrap_or_default(), opts.retain_ttl_secs),
    ));
    let stats = Arc::new(ServeStats::new());
    let stop = Arc::new(AtomicBool::new(false));

    let app = router(retain.clone())
        .layer(middleware::from_fn_with_state(
            stats.clone(),
            record_stats_middleware,
        ))
        .layer(middleware::from_fn_with_state(auth, auth_middleware))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024));

    let addr: SocketAddr = format!("{}:{}", opts.host, opts.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let url = format!("http://{addr}");

    let stop_serve = stop.clone();
    let stop_after = stop.clone();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while !stop_serve.load(Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await
        {
            eprintln!("serve error: {e}");
        }
        stop_after.store(true, Ordering::Relaxed);
    });

    let interactive = is_tty_stdio() && !is_headless_env();
    if interactive {
        println!("MetaDissect JSON API: {url}");
        println!("  GET  /api/health");
        println!("  POST /api/analyze       (multipart file)");
        println!("  POST /api/analyze-text  (JSON html|json)");
        println!("  POST /api/fetch         (JSON url, SSRF-safe)");
        #[cfg(feature = "tui")]
        {
            let stats_dash = stats.clone();
            let stop_dash = stop.clone();
            tokio::task::spawn_blocking(move || {
                let _ = run_serve_dashboard(
                    stats_dash,
                    stop_dash,
                    ServeDashboardOptions {
                        title: "MetaDissect API".into(),
                        url: url.clone(),
                    },
                );
            });
        }
    } else {
        println!("{url}");
    }

    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn record_stats_middleware(
    State(stats): State<Arc<ServeStats>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let route = req.uri().path().to_string();
    let start = Instant::now();
    let res = next.run(req).await;
    stats.record(&route, res.status().as_u16(), start.elapsed());
    res
}

#[derive(Clone)]
struct ServeAuth {
    host: String,
    token: Option<String>,
}

async fn auth_middleware(
    State(auth): State<ServeAuth>,
    headers: axum::http::HeaderMap,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let query_token = query_token_param(req.uri().query());
    if check_serve_token(
        &auth.host,
        auth.token.as_deref(),
        provided,
        query_token,
    )
    .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(req).await
}

pub fn router(retain: Arc<RetainStore>) -> Router {
    Router::new()
        .route("/meta-ui/shell.css", get(shell_css_handler))
        .route("/meta-ui/shell.js", get(shell_js_handler))
        .route("/api/health", get(health))
        .route("/api/retained", get(retained_list))
        .route("/api/analyze", post(analyze_upload))
        .route("/api/analyze-text", post(analyze_text))
        .route("/api/fetch", post(fetch_url))
        .with_state(AppState { retain })
}

#[derive(Clone)]
struct AppState {
    retain: Arc<RetainStore>,
}

async fn shell_css_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, shell_css_mime())],
        shell_css(),
    )
}

async fn shell_js_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, shell_js_mime())],
        shell_js(),
    )
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "name": "metadissect",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn retained_list(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let session = session_id(&headers);
    let items = state.retain.list_session(&session);
    Json(serde_json::json!({ "session": session, "items": items }))
}

fn session_id(headers: &axum::http::HeaderMap) -> String {
    if let Some(v) = headers.get("x-meta-session").and_then(|h| h.to_str().ok()) {
        return v.to_string();
    }
    if let Some(cookie) = headers.get(axum::http::header::COOKIE).and_then(|h| h.to_str().ok()) {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(id) = part.strip_prefix("meta_session=") {
                return id.to_string();
            }
        }
    }
    "default".to_string()
}

async fn analyze_upload(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(field) = multipart.next_field().await.map_err(AppError::bad)? {
        let name = field.file_name().unwrap_or("upload").to_string();
        let data = field.bytes().await.map_err(AppError::bad)?;
        let session = session_id(&headers);
        state.retain.store(&session, &name, &data);
        let analysis = analyze_buffer(&data, AnalyzeOptions::from_filename(name));
        return Ok(Json(serde_json::to_value(analysis).map_err(AppError::bad)?));
    }
    Err(AppError::bad("missing file"))
}

#[derive(Deserialize)]
struct TextReq {
    text: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    filename: Option<String>,
}

async fn analyze_text(Json(req): Json<TextReq>) -> Result<Json<serde_json::Value>, AppError> {
    let kind = req.kind.unwrap_or_else(|| "html".into());
    let mut analysis = if kind == "json" {
        analyze_json_string(&req.text, req.filename)
    } else {
        analyze_html_string(&req.text, req.filename)
    };
    analysis.source = if kind == "json" {
        Source::Json
    } else {
        Source::Html
    };
    Ok(Json(serde_json::to_value(analysis).map_err(AppError::bad)?))
}

#[derive(Deserialize)]
struct FetchReq {
    url: String,
}

async fn fetch_url(Json(req): Json<FetchReq>) -> Result<Json<serde_json::Value>, AppError> {
    let analysis = metadissect::fetch::fetch_and_analyze(&req.url)
        .await
        .map_err(AppError::bad)?;
    Ok(Json(serde_json::to_value(analysis).map_err(AppError::bad)?))
}

struct AppError {
    status: StatusCode,
    msg: String,
}

impl AppError {
    fn bad(err: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            msg: err.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.msg }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_ok() {
        let retain = Arc::new(RetainStore::new(RetainConfig::new(
            std::path::PathBuf::new(),
            3600,
        )));
        let app = router(retain);
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
