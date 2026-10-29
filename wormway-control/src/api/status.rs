//! Health, status and metrics endpoints.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde::Serialize;
use wormway_core::config::{ConfigSource, HealthCheckKind, Name, Protocol};
use wormway_runtime::{TargetReport, TargetState, UpstreamReport};

use super::Admin;

/// What `GET /api/v1/status` reports.
#[derive(Serialize)]
pub(crate) struct StatusResponse {
    /// Version of Wormway.
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

/// What `GET /api/v1/status/upstreams` reports.
#[derive(Serialize)]
pub(crate) struct UpstreamsResponse {
    /// Upstreams in effect, in name order.
    upstreams: Vec<UpstreamStatus>,
}

/// One upstream in the report.
#[derive(Serialize)]
struct UpstreamStatus {
    /// Name of the upstream.
    name: Name,
    /// How the active health checks probe the targets; `null` without active checks.
    health_check: Option<HealthCheckKind>,
    /// Whether the passive health checks are on.
    passive: bool,
    /// Every address the upstream balances over, in address order.
    targets: Vec<TargetStatus>,
}

/// One target in the report.
#[derive(Serialize)]
struct TargetStatus {
    /// Address of the target.
    address: SocketAddr,
    /// Host name the address was resolved from; `null` for IP addresses.
    host: Option<String>,
    /// Share of the requests relative to the other targets.
    weight: u32,
    /// `healthy`, `unhealthy` or `ejected`.
    state: &'static str,
    /// When the state began, as an RFC 3339 timestamp in UTC; `null` when no check has looked
    /// at the target.
    since: Option<String>,
    /// When an ejected target gets requests again; `null` for the other states.
    until: Option<String>,
    /// Why the target is unhealthy or ejected; `null` when it is healthy.
    reason: Option<String>,
}

impl From<UpstreamReport> for UpstreamStatus {
    /// Takes the report of the gateway.
    fn from(report: UpstreamReport) -> Self {
        Self {
            name: report.name,
            health_check: report.health_check,
            passive: report.passive,
            targets: report.targets.into_iter().map(TargetStatus::from).collect(),
        }
    }
}

impl From<TargetReport> for TargetStatus {
    /// Takes the report of the gateway.
    fn from(report: TargetReport) -> Self {
        let (state, until) = match report.state {
            TargetState::Healthy => ("healthy", None),
            TargetState::Unhealthy => ("unhealthy", None),
            TargetState::Ejected { until } => ("ejected", Some(rfc3339(until))),
        };
        Self {
            address: report.address,
            host: report.host,
            weight: report.weight,
            state,
            since: report.since.map(rfc3339),
            until,
            reason: report.reason,
        }
    }
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

/// `GET /api/v1/status/upstreams`: the upstreams in effect and the health of their targets.
pub(crate) async fn upstreams(State(admin): State<Arc<Admin>>) -> Json<UpstreamsResponse> {
    let upstreams = admin
        .server
        .upstreams()
        .into_iter()
        .map(Into::into)
        .collect();
    Json(UpstreamsResponse { upstreams })
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

/// Writes `time` as an RFC 3339 timestamp in UTC to the millisecond, as the database writes
/// them, such as `2026-10-29T08:30:00.000Z`. Times before 1970 are written as 1970.
fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (secs, millis) = (since_epoch.as_secs(), since_epoch.subsec_millis());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // The date `days` days after 1970-01-01, after Howard Hinnant's `civil_from_days`: years of
    // 400 years (eras), with years that start on March 1 so that leap days come last.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Timestamps match those of Python's datetime, leap days and milliseconds included.
    #[test]
    fn writes_rfc3339_timestamps() {
        let at = |millis: u64| UNIX_EPOCH + Duration::from_millis(millis);
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(at(951_782_400_000)), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_700_000_000_123)), "2023-11-14T22:13:20.123Z");
        assert_eq!(rfc3339(at(1_761_696_000_000)), "2025-10-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(4_102_444_799_999)), "2099-12-31T23:59:59.999Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01T00:00:00.000Z"
        );
    }
}
