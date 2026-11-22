//! RFC 7807 Problem Details error implementation for REST API.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Largest framework error body rewritten by [`api_error_envelope_middleware`].
///
/// Axum's extractor, method and media-type rejections are short plain-text
/// messages. The cap keeps a pathological handler response from being buffered.
const MAX_FRAMEWORK_ERROR_BODY: usize = 16 * 1024;

/// RFC 7807 Problem Details response object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    /// URI reference identifying the problem type.
    #[serde(rename = "type")]
    pub error_type: String,
    /// Short human-readable summary of the problem.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Detailed explanation specific to this occurrence.
    pub detail: String,
    /// Optional URI reference identifying the specific occurrence of the problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Restart-only configuration fields that caused a 409 Conflict (D11).
    ///
    /// Present only on configuration writes rejected because they change a
    /// setting that is read at process start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_required: Option<Box<Vec<String>>>,
    /// `Retry-After` seconds for a 429 response. Never serialized into the
    /// problem body; the response builder turns it into a header. `u16` keeps
    /// `ProblemDetails` small (the limiter windows are at most one minute).
    #[serde(skip)]
    #[schema(ignore)]
    pub retry_after_secs: Option<u16>,
}

impl ProblemDetails {
    pub fn new(status: StatusCode, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            error_type: format!("https://sito.network/errors/{}", status.as_u16()),
            title: title.into(),
            status: status.as_u16(),
            detail: detail.into(),
            instance: None,
            restart_required: None,
            retry_after_secs: None,
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "Bad Request", detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized", detail)
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "Forbidden", detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "Not Found", detail)
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "Conflict", detail)
    }

    /// Builds a 409 carrying the restart-only field list (D11).
    pub fn conflict_with_restart(restart_required: Vec<String>, detail: impl Into<String>) -> Self {
        let mut problem = Self::conflict(detail);
        problem.restart_required = Some(Box::new(restart_required));
        problem
    }

    pub fn too_many_requests(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "Too Many Requests", detail)
    }

    /// Builds a 429 that carries an explicit `Retry-After` in seconds.
    #[must_use]
    pub fn too_many_requests_with_retry(detail: impl Into<String>, retry_after_secs: u16) -> Self {
        let mut problem = Self::too_many_requests(detail);
        problem.retry_after_secs = Some(retry_after_secs);
        problem
    }

    pub fn internal_error(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            detail,
        )
    }

    /// Renders this problem with a one-second `Retry-After` hint.
    ///
    /// Used by rate-limited endpoints so a polling client backs off instead of
    /// immediately retrying an expensive request.
    #[must_use]
    pub fn into_response_with_retry_after(mut self) -> Response {
        self.retry_after_secs = Some(1);
        self.into_response()
    }
}

/// Normalizes framework-generated client errors under `/api/v2` into the
/// `ProblemDetails` envelope.
///
/// Handler errors already return `application/problem+json`, but errors
/// produced by Axum before a handler runs (malformed JSON, an invalid query or
/// path parameter, `415 Unsupported Media Type`, `413 Payload Too Large`,
/// `405 Method Not Allowed`, `426 Upgrade Required`) use a plain-text or empty
/// body. Operations already document a `ProblemDetails` body for `400` (and
/// `415` on some routes), so a client that parses one 400 must not receive a
/// different body for another 400. The full framework-status inventory lives in
/// `docs/2.0-api-errors.md`; it is not repeated on every OpenAPI operation.
///
/// Deliberate exceptions stay untouched:
/// - the unknown-path fallback (`404`) is documented as `application/json`;
/// - the first-boot gate (`503`) is a server-side gate documented as the
///   plain-text `Setup not completed` signal, and `sito healthcheck` matches
///   that text;
/// - UI paths are outside the `/api/v2` scope.
pub(crate) async fn api_error_envelope_middleware(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let response = next.run(request).await;
    normalize_api_error_envelope(response, &path).await
}

async fn normalize_api_error_envelope(response: Response, path: &str) -> Response {
    if path != "/api/v2" && !path.starts_with("/api/v2/") {
        return response;
    }
    let status = response.status();
    // Client errors only: handler 4xx/5xx responses already carry
    // `application/problem+json`, the fallback 404 carries `application/json`,
    // and the setup gate is a 503.
    if !status.is_client_error() {
        return response;
    }
    let plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.to_ascii_lowercase().starts_with("text/plain"));
    if !plain_text {
        return response;
    }

    let (parts, body) = response.into_parts();
    let headers = parts.headers;
    let Ok(bytes) = axum::body::to_bytes(body, MAX_FRAMEWORK_ERROR_BODY).await else {
        // The cap was exceeded. The body cannot be restored; answer with the
        // same status and the generic title rather than dropping the error.
        return problem_response(status, String::new(), headers);
    };
    let detail = String::from_utf8_lossy(&bytes).trim().to_string();
    problem_response(status, detail, headers)
}

fn problem_response(status: StatusCode, detail: String, headers: HeaderMap) -> Response {
    let detail = if detail.is_empty() {
        if status == StatusCode::METHOD_NOT_ALLOWED {
            "The HTTP method is not allowed for this endpoint.".to_string()
        } else {
            status
                .canonical_reason()
                .unwrap_or("The request was rejected.")
                .to_string()
        }
    } else {
        detail
    };
    let title = status.canonical_reason().unwrap_or("Request Failed");
    let mut response = ProblemDetails::new(status, title, detail).into_response();
    // Preserve `Allow` on a 405 and any other non-entity headers. `Content-Length`
    // describes the replaced body, so it must not survive.
    let mut headers = headers;
    headers.remove(header::CONTENT_TYPE);
    headers.remove(header::CONTENT_LENGTH);
    response.headers_mut().extend(headers);
    response
}

impl IntoResponse for ProblemDetails {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let retry_after = self.retry_after_secs;
        let body = serde_json::to_string(&self).unwrap_or_else(|_| "{}".to_string());

        let mut response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/problem+json")
            .body(axum::body::Body::from(body))
            .unwrap_or_else(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to render error response",
                )
                    .into_response()
            });
        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}
