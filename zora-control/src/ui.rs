//! The dashboard: the files built from `ui/`, served under `/ui/` without a token. The data
//! it shows comes from the Admin API, which needs the token.
//!
//! Release builds embed `ui/dist` at compile time. Debug builds read it from disk, so a new
//! `pnpm build` shows up without compiling zora again. Without `ui/dist` the dashboard pages
//! explain how to build it.

use std::borrow::Cow;
use std::path::Path as FilePath;

use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use rust_embed::RustEmbed;

/// The built dashboard.
#[derive(RustEmbed)]
#[folder = "../ui/dist/"]
#[allow_missing = true]
pub(crate) struct Dist;

/// Path of the dashboard.
const BASE: &str = "/ui/";

/// Files load only from this origin, and no other site may frame the dashboard.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; img-src 'self' data:; \
     object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Built files under `assets/` have a content hash in their name, so they never change.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// Media type of HTML.
const HTML: &str = "text/html; charset=utf-8";

/// Page shown when the dashboard was not built into this binary.
const PLACEHOLDER: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>zora</title>
</head>
<body>
<h1>The dashboard is not built into this binary</h1>
<p>Build it with <code>pnpm --dir ui install</code> and <code>pnpm --dir ui build</code>,
then build zora again.</p>
<p>The Admin API under <code>/api/v1/</code> works without it.</p>
</body>
</html>
"#;

/// Routes of the dashboard in `E`. `/` and `/ui` lead to `/ui/`.
pub(crate) fn routes<E, S>() -> Router<S>
where
    E: RustEmbed + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", get(redirect))
        .route("/ui", get(redirect))
        .route("/ui/", get(entry::<E>))
        .route("/ui/{*path}", get(file::<E>))
}

/// Sends the browser to the dashboard.
async fn redirect() -> Redirect {
    Redirect::to(BASE)
}

/// `GET /ui/`: the entry page.
async fn entry<E: RustEmbed>() -> Response {
    entry_page::<E>()
}

/// `GET /ui/{path}`: a built file. Paths without an extension are routes of the dashboard
/// itself and get the entry page, which shows them.
async fn file<E: RustEmbed>(Path(path): Path<String>) -> Response {
    if path.split('/').any(|segment| segment == "..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(file) = E::get(&path) {
        let cache = if path.starts_with("assets/") {
            IMMUTABLE
        } else {
            "no-cache"
        };
        return respond(StatusCode::OK, content_type(&path), cache, file.data);
    }
    if FilePath::new(&path).extension().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    entry_page::<E>()
}

/// The entry page, or the placeholder when the dashboard was not built.
fn entry_page<E: RustEmbed>() -> Response {
    match E::get("index.html") {
        Some(file) => respond(StatusCode::OK, HTML, "no-cache", file.data),
        None => respond(
            StatusCode::NOT_FOUND,
            HTML,
            "no-cache",
            Cow::Borrowed(PLACEHOLDER.as_bytes()),
        ),
    }
}

/// Answers with `body` and the headers every dashboard file gets.
fn respond(
    status: StatusCode,
    content_type: &'static str,
    cache: &'static str,
    body: Cow<'static, [u8]>,
) -> Response {
    let headers = [
        (header::CONTENT_TYPE, content_type),
        (header::CACHE_CONTROL, cache),
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
    ];
    (status, headers, body).into_response()
}

/// Media type of a built file, from its extension.
fn content_type(path: &str) -> &'static str {
    match FilePath::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("html") => HTML,
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderMap, Request};
    use tower::ServiceExt;

    use super::*;

    /// A small built dashboard.
    #[derive(RustEmbed)]
    #[folder = "tests/fixtures/ui/"]
    struct Built;

    /// A dashboard that was not built.
    #[derive(RustEmbed)]
    #[folder = "tests/fixtures/missing/"]
    #[allow_missing = true]
    struct Missing;

    /// Requests `path` from the dashboard in `E` and returns the status, headers and body.
    async fn get<E: RustEmbed + Send + Sync + 'static>(
        path: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::get(path).body(Body::empty()).unwrap();
        let response = routes::<E, ()>().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (
            parts.status,
            parts.headers,
            String::from_utf8(bytes.to_vec()).unwrap(),
        )
    }

    /// `/` and `/ui` redirect to `/ui/`.
    #[tokio::test]
    async fn leads_to_the_dashboard() {
        for path in ["/", "/ui"] {
            let (status, headers, _) = get::<Built>(path).await;
            assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
            assert_eq!(headers[header::LOCATION], "/ui/");
        }
    }

    /// The entry page is revalidated on every load and carries the security headers.
    #[tokio::test]
    async fn serves_the_entry_page() {
        let (status, headers, body) = get::<Built>("/ui/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], HTML);
        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY
        );
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(body.contains("fixture dashboard"), "{body}");
    }

    /// Hashed files are cached for good and typed by their extension.
    #[tokio::test]
    async fn serves_built_files() {
        let (status, headers, body) = get::<Built>("/ui/assets/app-1a2b3c.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(headers[header::CACHE_CONTROL], IMMUTABLE);
        assert!(body.contains("fixture script"), "{body}");
    }

    /// Paths without an extension get the entry page, which routes in the browser.
    #[tokio::test]
    async fn shows_dashboard_routes_with_the_entry_page() {
        for path in ["/ui/login", "/ui/versions/3"] {
            let (status, _, body) = get::<Built>(path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert!(body.contains("fixture dashboard"), "{path}: {body}");
        }
    }

    /// Missing files and paths that climb out of the dashboard are not found.
    #[tokio::test]
    async fn refuses_missing_files_and_paths_outside() {
        for path in [
            "/ui/assets/missing.js",
            "/ui/../Cargo.toml",
            "/ui/assets/../../lib.rs",
        ] {
            let (status, _, _) = get::<Built>(path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// Without a build every page explains how to make one.
    #[tokio::test]
    async fn explains_a_missing_build() {
        for path in ["/ui/", "/ui/versions"] {
            let (status, headers, body) = get::<Missing>(path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(headers[header::CONTENT_TYPE], HTML);
            assert!(body.contains("pnpm --dir ui build"), "{path}: {body}");
        }
    }
}
