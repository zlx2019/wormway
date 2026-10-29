//! Health of the targets of the upstreams: the gateway reports it, and the Admin API shows it.

use std::net::SocketAddr;
use std::time::SystemTime;

use wormway_core::config::{HealthCheckKind, Name};

/// Reports the health of the targets of the upstreams in effect.
pub trait HealthReport: Send + Sync + 'static {
    /// Returns every upstream in effect, in name order, with its targets.
    fn upstreams(&self) -> Vec<UpstreamReport>;
}

/// An upstream and the health of its targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamReport {
    /// Name of the upstream.
    pub name: Name,
    /// How the active health checks probe the targets; `None` without active checks.
    pub health_check: Option<HealthCheckKind>,
    /// Whether the passive health checks are on.
    pub passive: bool,
    /// Every address that the upstream balances over, in address order.
    pub targets: Vec<TargetReport>,
}

/// A target of an upstream and its health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetReport {
    /// Address of the target.
    pub address: SocketAddr,
    /// Host name that the address was resolved from, if any.
    pub host: Option<String>,
    /// Share of the requests relative to the other targets.
    pub weight: u32,
    /// Whether the target gets requests.
    pub state: TargetState,
    /// When the state began: when the result of the active checks last changed, or when the
    /// passive checks took the target out. `None` when no check has looked at the target.
    pub since: Option<SystemTime>,
    /// Why the target is unhealthy or out.
    pub reason: Option<String>,
}

/// Whether a target gets requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetState {
    /// It gets requests: its checks pass, or it has none.
    Healthy,
    /// The active checks failed: it gets no requests until its probes pass again.
    Unhealthy,
    /// The passive checks took it out: it gets no requests until `until`, unless every other
    /// target of its upstream is out as well.
    Ejected {
        /// When it gets requests again.
        until: SystemTime,
    },
}
