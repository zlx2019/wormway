//! Configuration endpoints: read, validate, replace, list versions and roll back.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::info;
use zora_core::config::{ConfigSource, DynamicConfig};

use super::Admin;
use super::error::ApiError;
use crate::store::{ChangeSource, SavedVersion};

/// Body of `PUT /api/v1/config` and `POST /api/v1/config/validate`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigRequest {
    /// The dynamic settings.
    config: DynamicConfig,
    /// Note saved with the version.
    #[serde(default)]
    comment: String,
}

/// The dynamic settings in effect.
#[derive(Serialize)]
struct ConfigResponse {
    /// Where the dynamic settings come from.
    source: ConfigSource,
    /// Saved version in effect; `null` in file mode and before the first change.
    version: Option<i64>,
    /// The dynamic settings.
    config: DynamicConfig,
}

/// Outcome of a change.
#[derive(Serialize)]
pub(crate) struct ChangeResponse {
    /// Saved version in effect after the request.
    version: Option<i64>,
    /// Whether a new version was saved; `false` when the settings were already in effect.
    changed: bool,
}

/// Query of `GET /api/v1/config/versions`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionsQuery {
    /// Maximum number of versions, 1 to 500, 50 by default.
    limit: Option<u32>,
    /// Only versions older than this one.
    before: Option<i64>,
}

/// A page of versions.
#[derive(Serialize)]
pub(crate) struct VersionsResponse {
    /// Newest first.
    versions: Vec<SavedVersion>,
}

/// One version with its settings.
#[derive(Serialize)]
pub(crate) struct VersionResponse {
    /// The version.
    #[serde(flatten)]
    version: SavedVersion,
    /// Its dynamic settings.
    config: DynamicConfig,
}

/// `GET /api/v1/config`: the dynamic settings in effect, with the saved version as `ETag`.
pub(crate) async fn show(State(admin): State<Arc<Admin>>) -> Response {
    // Changes hold this lock, so the version and the settings belong together.
    let current = admin.current.lock().await;
    let snapshot = admin.server.snapshot();
    let body = ConfigResponse {
        source: snapshot.config.config.source,
        version: *current,
        config: snapshot.config.dynamic(),
    };
    let mut response = Json(body).into_response();
    if let Some(version) = *current
        && let Ok(etag) = HeaderValue::from_str(&format!("\"{version}\""))
    {
        response.headers_mut().insert(header::ETAG, etag);
    }
    response
}

/// `POST /api/v1/config/validate`: checks dynamic settings without applying them.
pub(crate) async fn validate(
    State(admin): State<Arc<Admin>>,
    body: Result<Json<ConfigRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(request) = body?;
    let mut config = admin.server.snapshot().config.clone();
    config.set_dynamic(request.config);
    admin.server.validate(&config)?;
    Ok(Json(serde_json::json!({ "valid": true })))
}

/// `PUT /api/v1/config`: saves new dynamic settings as a version and applies them. An
/// `If-Match` header with a version number guards against overwriting a concurrent change.
pub(crate) async fn replace(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    body: Result<Json<ConfigRequest>, JsonRejection>,
) -> Result<Json<ChangeResponse>, ApiError> {
    let Json(request) = body?;
    admin.require_database_source()?;
    let mut current = admin.current.lock().await;
    check_if_match(&headers, *current)?;
    let response = change(&admin, &mut current, request.config, &request.comment).await?;
    Ok(Json(response))
}

/// `GET /api/v1/config/versions`: saved versions, newest first.
pub(crate) async fn versions(
    State(admin): State<Arc<Admin>>,
    query: Result<Query<VersionsQuery>, QueryRejection>,
) -> Result<Json<VersionsResponse>, ApiError> {
    let Query(query) = query?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let versions = admin.store.versions(limit, query.before).await?;
    Ok(Json(VersionsResponse { versions }))
}

/// `GET /api/v1/config/versions/{id}`: one saved version with its settings.
pub(crate) async fn version(
    State(admin): State<Arc<Admin>>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<VersionResponse>, ApiError> {
    let Path(id) = id?;
    let (version, config) = admin
        .store
        .version(id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("configuration version {id}")))?;
    Ok(Json(VersionResponse { version, config }))
}

/// `POST /api/v1/config/versions/{id}/rollback`: saves the settings of an older version as a
/// new version and applies them.
pub(crate) async fn rollback(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<ChangeResponse>, ApiError> {
    let Path(id) = id?;
    admin.require_database_source()?;
    let mut current = admin.current.lock().await;
    check_if_match(&headers, *current)?;
    let (_, config) = admin
        .store
        .version(id)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("configuration version {id}")))?;
    let comment = format!("rollback to version {id}");
    Ok(Json(change(&admin, &mut current, config, &comment).await?))
}

/// Saves `config` as a new version and switches to it, unless it is already in effect.
///
/// The switch is prepared first, so the version is only saved if it can be applied, and only
/// applied once it is saved. `current` is the guarded saved version in effect.
async fn change(
    admin: &Admin,
    current: &mut Option<i64>,
    config: DynamicConfig,
    comment: &str,
) -> Result<ChangeResponse, ApiError> {
    let running = admin.server.snapshot();
    if running.config.dynamic() == config {
        return Ok(ChangeResponse {
            version: *current,
            changed: false,
        });
    }
    let mut next = running.config.clone();
    next.set_dynamic(config.clone());
    let prepared = admin.server.prepare(next).await?;
    let saved = admin
        .store
        .save_version(&config, ChangeSource::Api, comment)
        .await?;
    prepared.commit();
    *current = Some(saved.id);
    info!(
        version = saved.id,
        "configuration changed through the Admin API"
    );
    Ok(ChangeResponse {
        version: Some(saved.id),
        changed: true,
    })
}

/// Checks an `If-Match` header, if present, against the saved version in effect. It holds a
/// version number, quoted or not, or `*` for any version.
fn check_if_match(headers: &HeaderMap, current: Option<i64>) -> Result<(), ApiError> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let expected = value.to_str().unwrap_or_default().trim();
    let expected = expected.trim_start_matches("W/").trim_matches('"');
    let current_text = current.map(|version| version.to_string());
    if expected == "*" || current_text.as_deref() == Some(expected) {
        return Ok(());
    }
    let in_effect = current_text.unwrap_or_else(|| "none".to_owned());
    Err(ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "version_mismatch",
        format!("the configuration in effect is version {in_effect}, not {expected}"),
    ))
}
