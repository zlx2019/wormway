//! The credentials of consumers: passwords, kept as bcrypt hashes, and API keys, made here and
//! shown once, kept as SHA-256 hashes.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wormway_core::config::{ApiKeyHash, Consumer, Name, PasswordHash};

use super::Admin;
use super::config::ChangeResponse;
use super::entity::{Edit, etag, with_etag};
use super::error::ApiError;
use crate::token::random_hex;

/// Cost of the bcrypt hashes of new passwords: some tens of milliseconds of CPU per check,
/// which the gateway caches. `htpasswd -B` uses 5, which is weak.
const BCRYPT_COST: u32 = 10;
/// The longest password: bcrypt reads the first 72 bytes only, so longer ones are refused
/// rather than cut.
const MAX_PASSWORD_BYTES: usize = 72;
/// Random bytes of a new API key, which is written as twice as many hex digits.
const API_KEY_BYTES: usize = 32;

/// Body of `PUT /api/v1/consumers/{name}/password`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordRequest {
    /// The new password.
    password: String,
}

/// Answer of `POST /api/v1/consumers/{name}/api-keys`.
#[derive(Serialize)]
pub(crate) struct ApiKeyResponse {
    /// The version saved with the key.
    #[serde(flatten)]
    change: ChangeResponse,
    /// The new key. Only its hash is kept, so this is the only time it is shown.
    key: String,
    /// The hash of the key, as the consumer lists it.
    hash: ApiKeyHash,
}

/// `PUT /api/v1/consumers/{name}/password`: sets the password that a consumer signs in with
/// through Basic authentication, as a new version. Only its bcrypt hash is kept.
pub(crate) async fn set_password(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    name: Result<Path<Name>, PathRejection>,
    body: Result<Json<PasswordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(name) = name?;
    let Json(request) = body?;
    if request.password.is_empty() || request.password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!("the password must have 1 to {MAX_PASSWORD_BYTES} bytes"),
        ));
    }
    let mut edit = Edit::start(&admin, &headers).await?;
    let consumer = edit.existing::<Consumer>(&headers, &name)?;
    consumer.password_hash = Some(hash_password(request.password).await?);
    let tag = etag(&*consumer);
    let outcome = edit
        .finish(&format!("set the password of consumers.{name}"))
        .await?;
    Ok(with_etag(Json(outcome).into_response(), &tag))
}

/// `POST /api/v1/consumers/{name}/api-keys`: makes a new API key for a consumer, as a new
/// version. The answer holds the key; only its hash is kept, so it cannot be shown again.
pub(crate) async fn add_api_key(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    name: Result<Path<Name>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(name) = name?;
    let mut edit = Edit::start(&admin, &headers).await?;
    let consumer = edit.existing::<Consumer>(&headers, &name)?;
    let key = random_hex(API_KEY_BYTES).map_err(|error| ApiError::internal(&error))?;
    let digest: [u8; 32] = Sha256::digest(&key).into();
    let hash = ApiKeyHash::from(digest);
    consumer.api_keys.push(hash);
    let tag = etag(&*consumer);
    let change = edit
        .finish(&format!("add an API key to consumers.{name}"))
        .await?;
    let answer = ApiKeyResponse { change, key, hash };
    Ok(with_etag(
        (StatusCode::CREATED, Json(answer)).into_response(),
        &tag,
    ))
}

/// Hashes `password` with bcrypt on the blocking pool, as it takes some tens of milliseconds.
async fn hash_password(password: String) -> Result<PasswordHash, ApiError> {
    let hashed = tokio::task::spawn_blocking(move || bcrypt::hash(password, BCRYPT_COST))
        .await
        .map_err(|error| ApiError::internal(&error))?
        .map_err(|error| ApiError::internal(&error))?;
    PasswordHash::try_from(hashed).map_err(|error| ApiError::internal(&error))
}
