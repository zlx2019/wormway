//! Token authentication.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::Admin;
use super::error::ApiError;

/// Lets a request through only if it carries `Authorization: Bearer <token>`.
pub(crate) async fn authorize(
    State(admin): State<Arc<Admin>>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer);
    if presented.is_some_and(|token| admin.token.matches(token)) {
        next.run(request).await
    } else {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or wrong token, send Authorization: Bearer <token>",
        )
        .into_response()
    }
}

/// Returns the token of a `Bearer` credential. The scheme is case-insensitive.
fn bearer(credential: &str) -> Option<&str> {
    let (scheme, token) = credential.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only Bearer credentials yield a token.
    #[test]
    fn parses_bearer_credentials() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("bearer  abc "), Some("abc"));
        assert_eq!(bearer("Basic abc"), None);
        assert_eq!(bearer("Bearer"), None);
    }
}
