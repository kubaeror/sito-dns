//! RFC 7807 Problem Details error implementation for REST API.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
