//! Embedded static assets handler for HTMX, Alpine.js, uPlot, and CSS.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static"]
pub struct StaticAssets;

pub async fn static_handler(Path(path): Path<String>) -> Response {
    let clean_path = path.trim_start_matches('/');
    if let Some(file) = StaticAssets::get(clean_path) {
        let mime = mime_guess::from_path(clean_path).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, mime.as_ref())
            .header(CACHE_CONTROL, "public, max-age=86400")
            .body(axum::body::Body::from(file.data))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
