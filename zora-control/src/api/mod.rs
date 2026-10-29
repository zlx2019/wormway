//! The Admin API: status, configuration and metrics over HTTP, behind a bearer token.

mod auth;
mod config;
mod error;
mod status;

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use zora_core::config::ConfigSource;
use zora_runtime::Server;

use crate::prometheus::Metrics;
use crate::store::{Store, StoreError};
use crate::token::AdminToken;
use error::ApiError;

/// State of the Admin API.
pub struct Admin {
    /// The server whose configuration the API reads and changes.
    server: Arc<Server>,
    /// Saved versions of the dynamic settings.
    store: Store,
    /// Token that requests must present.
    token: AdminToken,
    /// Output of `/metrics`.
    metrics: Metrics,
    /// ID of this instance.
    instance: String,
    /// When the API started, for the uptime.
    started: Instant,
    /// Saved version in effect. Changes hold the lock from start to end, so they do not
    /// overlap.
    current: Mutex<Option<i64>>,
}

impl Admin {
    /// Creates the API for `server`. In database mode the newest saved version must be the one
    /// the server runs.
    pub async fn new(
        server: Arc<Server>,
        store: Store,
        token: AdminToken,
        metrics: Metrics,
    ) -> Result<Arc<Self>, StoreError> {
        let instance = store.instance_id().await?;
        let current = match server.snapshot().config.config.source {
            ConfigSource::Db => store.latest_version().await?.map(|(version, _)| version.id),
            ConfigSource::File => None,
        };
        Ok(Arc::new(Self {
            server,
            store,
            token,
            metrics,
            instance,
            started: Instant::now(),
            current: Mutex::new(current),
        }))
    }

    /// Returns the routes of the API, and of the dashboard with the `ui` feature. Everything
    /// except `/healthz` and the dashboard files needs the token.
    pub fn router(self: &Arc<Self>) -> Router {
        let protected = Router::new()
            .route("/api/v1/status", get(status::status))
            .route("/api/v1/config", get(config::show).put(config::replace))
            .route("/api/v1/config/validate", post(config::validate))
            .route("/api/v1/config/versions", get(config::versions))
            .route("/api/v1/config/versions/{id}", get(config::version))
            .route(
                "/api/v1/config/versions/{id}/rollback",
                post(config::rollback),
            )
            .route("/metrics", get(status::metrics))
            .route_layer(middleware::from_fn_with_state(
                self.clone(),
                auth::authorize,
            ));
        let router = Router::new()
            .route("/healthz", get(status::healthz))
            .merge(protected);
        #[cfg(feature = "ui")]
        let router = router.merge(crate::ui::routes::<crate::ui::Dist, _>());
        router
            .fallback(error::not_found)
            .method_not_allowed_fallback(error::method_not_allowed)
            .with_state(self.clone())
    }

    /// Refuses changes when the dynamic settings come from the configuration file.
    fn require_database_source(&self) -> Result<(), ApiError> {
        match self.server.snapshot().config.config.source {
            ConfigSource::Db => Ok(()),
            ConfigSource::File => Err(ApiError::new(
                StatusCode::CONFLICT,
                "read_only",
                "the dynamic settings come from the configuration file (config.source = \"file\"): \
                 edit the file and send SIGHUP",
            )),
        }
    }
}

/// Serves the Admin API on `listener` until `shutdown` completes, then lets the requests in
/// progress finish.
pub async fn serve(
    listener: TcpListener,
    admin: Arc<Admin>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(listener, admin.router())
        .with_graceful_shutdown(shutdown)
        .await
}
