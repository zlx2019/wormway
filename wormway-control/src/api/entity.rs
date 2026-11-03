//! Entity endpoints: the listeners, routes, upstreams, certificates, consumers and JWT settings
//! one at a time. Every change is saved as a version, like a change of the whole configuration.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::sync::MutexGuard;
use wormway_core::config::{
    Certificate, Consumer, DynamicConfig, Jwt, Listener, Name, Route, Upstream,
};

use super::Admin;
use super::config::{ChangeResponse, change, change_source};
use super::error::ApiError;
use crate::store::ChangeSource;

/// A kind of entity: one of the tables of the dynamic settings, by name.
pub(crate) trait Entity: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Name of the table, in the configuration and in the paths of the API, such as `routes`.
    const TABLE: &'static str;

    /// Returns the table of this kind in `config`.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self>;
}

impl Entity for Listener {
    const TABLE: &'static str = "listeners";

    /// The listeners.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.listeners
    }
}

impl Entity for Route {
    const TABLE: &'static str = "routes";

    /// The routes.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.routes
    }
}

impl Entity for Upstream {
    const TABLE: &'static str = "upstreams";

    /// The upstreams.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.upstreams
    }
}

impl Entity for Certificate {
    const TABLE: &'static str = "certificates";

    /// The certificates.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.certificates
    }
}

impl Entity for Consumer {
    const TABLE: &'static str = "consumers";

    /// The consumers.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.consumers
    }
}

impl Entity for Jwt {
    const TABLE: &'static str = "jwt";

    /// The settings that check JWTs.
    fn table(config: &mut DynamicConfig) -> &mut BTreeMap<Name, Self> {
        &mut config.jwt
    }
}

/// Adds the endpoints of every kind of entity to `router`.
pub(crate) fn routes(router: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    let router = table::<Listener>(router);
    let router = table::<Route>(router);
    let router = table::<Upstream>(router);
    let router = table::<Certificate>(router);
    let router = table::<Consumer>(router);
    table::<Jwt>(router)
}

/// Adds the endpoints of the entities of kind `E` to `router`.
fn table<E: Entity>(router: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    let path = format!("/api/v1/{}", E::TABLE);
    router.route(&path, get(list::<E>)).route(
        &format!("{path}/{{name}}"),
        get(show::<E>).put(put::<E>).delete(delete::<E>),
    )
}

/// A change of single entities in progress: the dynamic settings in effect, changed in place,
/// with the saved version locked until the change is saved and applied, or dropped.
pub(crate) struct Edit<'a> {
    /// The API.
    admin: &'a Admin,
    /// The saved version in effect, locked.
    current: MutexGuard<'a, Option<i64>>,
    /// The dynamic settings.
    config: DynamicConfig,
    /// Who makes the change.
    source: ChangeSource,
}

impl<'a> Edit<'a> {
    /// Starts a change for the request with `headers`. Only the database takes changes.
    pub(crate) async fn start(admin: &'a Admin, headers: &HeaderMap) -> Result<Self, ApiError> {
        let source = change_source(headers)?;
        admin.require_database_source()?;
        let current = admin.current.lock().await;
        let config = admin.server.snapshot().config.dynamic();
        Ok(Self {
            admin,
            current,
            config,
            source,
        })
    }

    /// Returns the table of kind `E`.
    pub(crate) fn table<E: Entity>(&mut self) -> &mut BTreeMap<Name, E> {
        E::table(&mut self.config)
    }

    /// Returns entity `name` of kind `E` if it exists and the conditions of `headers` hold for
    /// it.
    pub(crate) fn existing<E: Entity>(
        &mut self,
        headers: &HeaderMap,
        name: &Name,
    ) -> Result<&mut E, ApiError> {
        let entity = self
            .table::<E>()
            .get_mut(name)
            .ok_or_else(|| not_found::<E>(name))?;
        check_conditions(headers, name, Some(&*entity))?;
        Ok(entity)
    }

    /// Saves the changed settings as a new version with `comment` and applies them.
    pub(crate) async fn finish(mut self, comment: &str) -> Result<ChangeResponse, ApiError> {
        change(
            self.admin,
            &mut self.current,
            self.config,
            self.source,
            comment,
        )
        .await
    }
}

/// `GET /api/v1/{table}`: every entity of the table in effect, by name.
async fn list<E: Entity>(
    State(admin): State<Arc<Admin>>,
) -> Json<BTreeMap<&'static str, BTreeMap<Name, E>>> {
    let mut config = admin.server.snapshot().config.dynamic();
    let entities = std::mem::take(E::table(&mut config));
    Json(BTreeMap::from([(E::TABLE, entities)]))
}

/// `GET /api/v1/{table}/{name}`: one entity in effect, with its entity tag.
async fn show<E: Entity>(
    State(admin): State<Arc<Admin>>,
    name: Result<Path<Name>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(name) = name?;
    let mut config = admin.server.snapshot().config.dynamic();
    let entity = E::table(&mut config)
        .remove(&name)
        .ok_or_else(|| not_found::<E>(&name))?;
    let tag = etag(&entity);
    Ok(with_etag(Json(entity).into_response(), &tag))
}

/// `PUT /api/v1/{table}/{name}`: creates or replaces an entity, as a new version. Answers 201
/// when it creates the entity, with the entity tag it has now.
async fn put<E: Entity>(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    name: Result<Path<Name>, PathRejection>,
    body: Result<Json<E>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(name) = name?;
    let Json(entity) = body?;
    let mut edit = Edit::start(&admin, &headers).await?;
    let entities = edit.table::<E>();
    check_conditions(&headers, &name, entities.get(&name))?;
    let (status, verb) = if entities.contains_key(&name) {
        (StatusCode::OK, "replace")
    } else {
        (StatusCode::CREATED, "create")
    };
    let tag = etag(&entity);
    entities.insert(name.clone(), entity);
    let outcome = edit.finish(&format!("{verb} {}.{name}", E::TABLE)).await?;
    Ok(with_etag((status, Json(outcome)).into_response(), &tag))
}

/// `DELETE /api/v1/{table}/{name}`: removes an entity, as a new version. An entity that others
/// refer to stays: the problems name the settings that refer to it.
async fn delete<E: Entity>(
    State(admin): State<Arc<Admin>>,
    headers: HeaderMap,
    name: Result<Path<Name>, PathRejection>,
) -> Result<Json<ChangeResponse>, ApiError> {
    let Path(name) = name?;
    let mut edit = Edit::start(&admin, &headers).await?;
    edit.existing::<E>(&headers, &name)?;
    edit.table::<E>().remove(&name);
    let outcome = edit.finish(&format!("delete {}.{name}", E::TABLE)).await?;
    Ok(Json(outcome))
}

/// Returns the entity tag of `entity`: the first 16 bytes of the SHA-256 of its JSON, in hex.
/// It changes with the entity only, not with others.
pub(crate) fn etag(entity: &impl Serialize) -> String {
    let json = serde_json::to_vec(entity).unwrap_or_default();
    Sha256::digest(json)[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Adds entity tag `tag` to `response`, in quotes.
pub(crate) fn with_etag(mut response: Response, tag: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(&format!("\"{tag}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// Checks the conditions of `headers` against `entity`, entity `name` as it is in effect, if
/// it exists: `If-Match` lists entity tags that it must have one of, or `*` for any entity;
/// `If-None-Match` lists entity tags that it must have none of, or `*` for no entity at all.
fn check_conditions<E: Entity>(
    headers: &HeaderMap,
    name: &Name,
    entity: Option<&E>,
) -> Result<(), ApiError> {
    let tag = entity.map(etag);
    let at = format!("{}.{name}", E::TABLE);
    if let Some(listed) = headers.get(header::IF_MATCH)
        && !lists(listed, tag.as_deref())
    {
        let problem = if tag.is_some() {
            "has changed"
        } else {
            "does not exist"
        };
        return Err(precondition_failed(format!("{at} {problem}")));
    }
    if let Some(listed) = headers.get(header::IF_NONE_MATCH)
        && lists(listed, tag.as_deref())
    {
        return Err(precondition_failed(format!("{at} already exists")));
    }
    Ok(())
}

/// Whether the entity tags of a condition, `listed`, hold `tag`, that of an entity in effect:
/// as it is, in quotes, or as `*`. Weak tags never match. Without an entity, nothing matches.
fn lists(listed: &HeaderValue, tag: Option<&str>) -> bool {
    let Some(tag) = tag else {
        return false;
    };
    listed
        .to_str()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .any(|listed| listed == "*" || listed.trim_matches('"') == tag)
}

/// The entity is not as the conditions of the request ask.
fn precondition_failed(message: String) -> ApiError {
    ApiError::new(StatusCode::PRECONDITION_FAILED, "version_mismatch", message)
}

/// Entity `name` of kind `E` does not exist.
fn not_found<E: Entity>(name: &Name) -> ApiError {
    ApiError::not_found(format!("{}.{name}", E::TABLE))
}
