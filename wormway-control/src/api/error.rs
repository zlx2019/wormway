//! Error responses: `{"error": {"code": ..., "message": ..., "details": [...]}}`.

use std::error::Error;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tracing::error;
use wormway_core::config::{ConfigError, Issue};
use wormway_runtime::ApplyError;

use crate::store::StoreError;

/// An error answered to an Admin API request.
#[derive(Debug)]
pub(crate) struct ApiError {
    /// HTTP status.
    status: StatusCode,
    /// Stable, machine-readable code such as `invalid_config`.
    code: &'static str,
    /// Human-readable explanation.
    message: String,
    /// Problems with single settings, for `invalid_config`.
    details: Vec<Issue>,
}

impl ApiError {
    /// Creates an error without details.
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: Vec::new(),
        }
    }

    /// The configuration breaks rules; `details` names each problem.
    fn invalid_config(details: Vec<Issue>) -> Self {
        Self {
            details,
            ..Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_config",
                "the configuration is invalid",
            )
        }
    }

    /// The thing described by `what` does not exist.
    pub(crate) fn not_found(what: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{} not found", what.into()),
        )
    }
}

/// JSON shape of an error response.
#[derive(Serialize)]
struct Body<'a> {
    /// The error.
    error: Detail<'a>,
}

/// JSON shape of the error itself.
#[derive(Serialize)]
struct Detail<'a> {
    /// Machine-readable code.
    code: &'a str,
    /// Human-readable explanation.
    message: &'a str,
    /// Problems with single settings.
    #[serde(skip_serializing_if = "<[Issue]>::is_empty")]
    details: &'a [Issue],
}

impl IntoResponse for ApiError {
    /// Answers with the status and the JSON body.
    fn into_response(self) -> Response {
        let body = Body {
            error: Detail {
                code: self.code,
                message: &self.message,
                details: &self.details,
            },
        };
        let mut response = (self.status, Json(body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

impl From<ApplyError> for ApiError {
    /// Rule violations and unknown protocols are the client's to fix; the rest failed while
    /// switching.
    fn from(error: ApplyError) -> Self {
        match error {
            ApplyError::Config(ConfigError::Invalid(issues)) => Self::invalid_config(issues),
            ApplyError::Unsupported { listener, protocol } => Self::invalid_config(vec![Issue {
                path: format!("listeners.{listener}.protocol"),
                message: format!("protocol {protocol} is not available in this build"),
            }]),
            ApplyError::ShuttingDown => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "shutting_down",
                error.to_string(),
            ),
            other => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "apply_failed",
                with_causes(&other),
            ),
        }
    }
}

impl From<StoreError> for ApiError {
    /// Logs the cause and answers with a generic message.
    fn from(error: StoreError) -> Self {
        error!("Admin API request failed: {}", with_causes(&error));
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error, see the server log",
        )
    }
}

impl From<JsonRejection> for ApiError {
    /// A body that is not JSON or does not match the expected shape.
    fn from(rejection: JsonRejection) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    }
}

impl From<PathRejection> for ApiError {
    /// A path parameter of the wrong type.
    fn from(rejection: PathRejection) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    }
}

impl From<QueryRejection> for ApiError {
    /// Query parameters of the wrong type.
    fn from(rejection: QueryRejection) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    }
}

/// Answers requests to unknown paths.
pub(crate) async fn not_found() -> ApiError {
    ApiError::not_found("path")
}

/// Answers requests with a method the path does not support.
pub(crate) async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this path",
    )
}

/// Formats `error` followed by its causes, separated by `: `.
fn with_causes(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}
