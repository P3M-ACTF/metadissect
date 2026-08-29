use crate::analyze::analyze_buffer;
use crate::error::{MetaError, Result};
use crate::types::{AnalyzeOptions, Source};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

const MAX_BYTES: u64 = 50 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 15;

pub async fn fetch_and_analyze(url: &str) -> Result<crate::types::Analysis> {
    fetch_and_analyze_with(url, AnalyzeOptions::default()).await
}

/// Like [`fetch_and_analyze`], honoring extra options such as `verbose`.
pub async fn fetch_and_analyze_with(
    url: &str,
    extra: AnalyzeOptions,
) -> Result<crate::types::Analysis> {
    let parsed = Url::parse(url).map_err(|e| MetaError::Fetch(e.to_string()))?;
    validate_url(&parsed)?;
    resolve_and_reject(&parsed)?;

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let url = attempt.url().clone();
            if validate_url(&url).is_err() || resolve_and_reject(&url).is_err() {
                attempt.error(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("blocked redirect to {url}"),
                ))
            } else if attempt.previous().len() >= 5 {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| MetaError::Fetch(e.to_string()))?;

    let response = client
        .get(parsed.as_str())
        .send()
        .await
        .map_err(|e| MetaError::Fetch(e.to_string()))?;

    if let Some(remote) = response.remote_addr() {
        reject_ip(remote.ip())?;
    }

    if let Some(len) = response.content_length() {
        if len > MAX_BYTES {
            return Err(MetaError::TooLarge {
                size: len,
                limit: MAX_BYTES,
            });
        }
    }

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mime_hint = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_string());

    let mut bytes = Vec::new();
    let mut remaining = MAX_BYTES;
    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let n = chunk.len() as u64;
                if n > remaining {
                    return Err(MetaError::TooLarge {
                        size: MAX_BYTES + n,
                        limit: MAX_BYTES,
                    });
                }
                remaining -= n;
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(MetaError::Fetch(e.to_string())),
        }
    }

    let filename = parsed
        .path_segments()
        .and_then(|mut s| s.next_back())
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .to_string();

    let mut options = AnalyzeOptions::from_filename(filename);
    options.source = Some(Source::Url);
    options.source_url = Some(parsed.to_string());
    options.response_headers = headers;
    options.verbose = extra.verbose;
    options.max_embed_depth = extra.max_embed_depth;
    options.trust_anchors = extra.trust_anchors.clone();
    if mime_hint.is_some() {
        options.filename = options.filename.filter(|n| n.contains('.'));
        if options.filename.is_none() {
            options.filename = Some("download".into());
        }
    }
    Ok(analyze_buffer(&bytes, options))
}

fn validate_url(parsed: &Url) -> Result<()> {
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(MetaError::BlockedUrl(format!(
            "scheme {} is not allowed",
            parsed.scheme()
        )));
    }
    if let Some(host) = parsed.host_str() {
        reject_host(host)?;
    } else {
        return Err(MetaError::BlockedUrl("missing host".into()));
    }
    Ok(())
}

fn resolve_and_reject(parsed: &Url) -> Result<()> {
    let host = parsed
        .host_str()
        .ok_or_else(|| MetaError::BlockedUrl("missing host".into()))?;
    reject_host(host)?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| MetaError::Fetch(format!("DNS {host}: {e}")))?;
    let mut any = false;
    for addr in addrs {
        any = true;
        reject_ip(addr.ip())?;
    }
    if !any {
        return Err(MetaError::Fetch(format!("no addresses for {host}")));
    }
    Ok(())
}

fn reject_host(host: &str) -> Result<()> {
    let h = host.to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h == "0" {
        return Err(MetaError::BlockedUrl(host.into()));
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        reject_ip(ip)?;
    }
    Ok(())
}

pub fn reject_ip(ip: IpAddr) -> Result<()> {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(MetaError::BlockedUrl(ip.to_string()));
    }
    match ip {
        IpAddr::V4(v4) => reject_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return reject_v4(v4);
            }
            if is_link_local_v6(&v6) || is_unique_local_v6(&v6) {
                return Err(MetaError::BlockedUrl(ip.to_string()));
            }
            Ok(())
        }
    }
}

fn reject_v4(v4: Ipv4Addr) -> Result<()> {
    if v4.is_private() || v4.is_link_local() || v4.is_broadcast() {
        return Err(MetaError::BlockedUrl(v4.to_string()));
    }
    let o = v4.octets();
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return Err(MetaError::BlockedUrl(v4.to_string()));
    }
    Ok(())
}

fn is_link_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// fc00::/7 without depending on Rust 1.84 `is_unique_local`.
fn is_unique_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback_and_private() {
        assert!(reject_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(reject_ip("10.0.0.1".parse().unwrap()).is_err());
        assert!(reject_ip("192.168.1.1".parse().unwrap()).is_err());
        assert!(reject_ip("169.254.1.1".parse().unwrap()).is_err());
        assert!(reject_ip("100.64.0.1".parse().unwrap()).is_err());
        assert!(reject_ip("::1".parse().unwrap()).is_err());
        assert!(reject_ip("fc00::1".parse().unwrap()).is_err());
        assert!(reject_ip("fe80::1".parse().unwrap()).is_err());
        assert!(reject_ip("8.8.8.8".parse().unwrap()).is_ok());
    }

    #[test]
    fn blocks_localhost_host() {
        assert!(reject_host("localhost").is_err());
        assert!(reject_host("foo.localhost").is_err());
    }
}
