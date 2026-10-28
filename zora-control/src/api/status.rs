//! Health, status and metrics endpoints.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde::Serialize;
use zora_core::config::{ConfigSource, Name, Protocol};

use super::Admin;

/// What `GET /api/v1/status` reports.
#[derive(Serialize)]
pub(crate) struct StatusResponse {
    /// Version of zora.
    version: &'static str,
    /// ID of this instance.
    instance: String,
    /// Seconds since the Admin API started.
    uptime_seconds: u64,
    /// Where the dynamic settings come from and which saved version is in effect.
    config: ConfigStatus,
    /// Version of the snapshot in effect; it grows with every change, reloads included.
    snapshot: u64,
    /// Listeners with their bound addresses.
    listeners: Vec<ListenerStatus>,
}

/// Configuration part of the status.
#[derive(Serialize)]
struct ConfigStatus {
    /// Where the dynamic settings come from.
    source: ConfigSource,
    /// Saved version in effect; `null` in file mode and before the first change.
    version: Option<i64>,
}

/// One listener in the status.
#[derive(Serialize)]
struct ListenerStatus {
    /// Name of the listener.
    name: Name,
    /// Its protocol.
    protocol: Protocol,
    /// Addresses it is bound to.
    addresses: Vec<SocketAddr>,
}

/// `GET /healthz`: answers while the process runs. It needs no token.
pub(crate) async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// `GET /api/v1/status`: version, uptime, configuration and listeners.
pub(crate) async fn status(State(admin): State<Arc<Admin>>) -> Json<StatusResponse> {
    let version = *admin.current.lock().await;
    let snapshot = admin.server.snapshot();
    let mut bound = admin.server.listeners().await;
    let listeners = snapshot
        .config
        .listeners
        .iter()
        .map(|(name, listener)| ListenerStatus {
            name: name.clone(),
            protocol: listener.protocol,
            addresses: bound.remove(name).unwrap_or_default(),
        })
        .collect();
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        instance: admin.instance.clone(),
        uptime_seconds: admin.started.elapsed().as_secs(),
        config: ConfigStatus {
            source: snapshot.config.config.source,
            version,
        },
        snapshot: snapshot.version,
        listeners,
    })
}

/// `GET /metrics`: metrics in the Prometheus text format.
pub(crate) async fn metrics(State(admin): State<Arc<Admin>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        admin.metrics.render(),
    )
}
