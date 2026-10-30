//! The HTTP gateway of Wormway: serves the listeners with protocol `http` through Pingora and
//! routes their requests to upstreams.
//!
//! [`Gateway::register`] adds four parts to the [`Services`] of the runtime: the service factory of
//! protocol `http`, which gives every listener its own Pingora proxy, an engine that compiles the
//! routes and upstreams of each configuration into a snapshot shared by all listeners, the report
//! of the health of the upstreams, and the report of the traffic of the last minute, by route and
//! by upstream. Every request takes the snapshot in effect when it starts and keeps it until it
//! ends. Listeners with TLS present the certificates of [`Certificates`] and agree on HTTP/2 or
//! HTTP/1.1 during the handshake. With an [`AccessLog`], every request gets a line in it. Requests
//! and their attempts at targets are counted in the metrics of the process-wide recorder of the
//! `metrics` crate. Pingora types do not appear in the public API.

mod access_log;
mod compress;
mod headers;
mod health;
mod listener;
mod probe;
mod proxy;
mod route;
mod snapshot;
mod stats;
mod telemetry;
mod upstream;
mod upstream_tls;

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::server::configuration::ServerConf;
use wormway_core::config::Protocol;
use wormway_runtime::Services;
use wormway_tls::Certificates;

pub use crate::access_log::AccessLog;
use crate::listener::HttpListeners;
use crate::snapshot::{GatewaySnapshot, Report, Routing};

/// The HTTP gateway.
pub struct Gateway {
    /// Routes and upstreams in effect, shared by the listeners and the engine.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Pingora settings of every proxy.
    conf: Arc<ServerConf>,
    /// Certificates of the listeners with TLS.
    certificates: Certificates,
    /// Where the line of each request goes, if the access log is on.
    access_log: Option<AccessLog>,
}

impl Gateway {
    /// Creates a gateway for a data plane with `threads` worker threads, whose listeners with
    /// TLS present `certificates`. The number of threads sizes the pools of idle upstream
    /// connections.
    pub fn new(threads: usize, certificates: Certificates) -> Self {
        let conf = ServerConf {
            threads: threads.max(1),
            ..ServerConf::default()
        };
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(GatewaySnapshot::default())),
            conf: Arc::new(conf),
            certificates,
            access_log: None,
        }
    }

    /// Writes a line for every request to `access_log`.
    pub fn with_access_log(mut self, access_log: AccessLog) -> Self {
        self.access_log = Some(access_log);
        self
    }

    /// Registers the gateway with `services`: the service factory of protocol `http`, the
    /// engine of its routes and upstreams, and the reports of the health of the upstreams and of
    /// the traffic. The engine of the certificates is registered on its own, see
    /// [`Certificates::register`].
    pub fn register(self, services: &mut Services) {
        let routing = Routing::new(self.snapshot.clone(), self.certificates.clone());
        let report = Report(self.snapshot.clone());
        let traffic = stats::Report(self.snapshot.clone());
        telemetry::describe();
        let listeners =
            HttpListeners::new(self.snapshot, self.conf, self.certificates, self.access_log);
        services.register(Protocol::Http, listeners);
        services.add_engine(routing);
        services.set_health_report(report);
        services.set_stats_report(traffic);
    }
}
