//! Thin JSON HTTP API (no web UI). Bound to localhost by default.

use axum::extract::{DefaultBodyLimit, Multipart};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use metadissect::{
    analyze_buffer, analyze_html_string, analyze_json_string, AnalyzeOptions, Source,
};
use serde::Deserialize;
use std::net::SocketAddr;

pub async fn serve(host: &str, port: u16) -> anyhow::Result<()> {
    if host == "0.0.0.0" || host == "::" || host == "[::]" {
        eprintln!(
            "WARNING: binding to {host} exposes the analyzer on the network with no authentication."
        );
    }
    let app = router();
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let url = format!("http://{addr}");
    println!("MetaDissect JSON API: {url}");
    println!("  GET  /api/health");
    println!("  POST /api/analyze       (multipart file)");
    println!("  POST /api/analyze-text  (JSON html|json)");
    println!("  POST /api/fetch         (JSON url, SSRF-safe)");
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn router() -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/analyze", post(analyze_upload))
        .route("/api/analyze-text", post(analyze_text))
        .route("/api/fetch", post(fetch_url))
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "name": "metadissect",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn analyze_upload(mut multipart: Multipart) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(field) = multipart.next_field().await.map_err(AppError::bad)? {
        let name = field.file_name().unwrap_or("upload").to_string();
        let data = field.bytes().await.map_err(AppError::bad)?;
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
        let app = router();
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
