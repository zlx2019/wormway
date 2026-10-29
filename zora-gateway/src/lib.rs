//! The HTTP gateway of zora: serves the listeners with protocol `http` through Pingora and
//! routes their requests to upstreams.
//!
//! [`Gateway::register`] adds two parts to the [`Services`] of the runtime: the service factory
//! of protocol `http`, which gives every listener its own Pingora proxy, and an engine that
//! compiles the routes and upstreams of each configuration into a snapshot shared by all
//! listeners. Every request takes the snapshot in effect when it starts and keeps it until it
//! ends. Listeners with TLS present the certificates of [`Certificates`] and agree on HTTP/2 or
//! HTTP/1.1 during the handshake. Pingora types do not appear in the public API.

mod listener;
mod proxy;
mod snapshot;
mod upstream;

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::server::configuration::ServerConf;
use zora_core::config::Protocol;
use zora_runtime::Services;
use zora_tls::Certificates;

use crate::listener::HttpListeners;
use crate::snapshot::{GatewaySnapshot, Routing};

/// The HTTP gateway.
pub struct Gateway {
    /// Routes and upstreams in effect, shared by the listeners and the engine.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Pingora settings of every proxy.
    conf: Arc<ServerConf>,
    /// Certificates of the listeners with TLS.
    certificates: Certificates,
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
        }
    }

    /// Registers the gateway with `services`: the service factory of protocol `http` and the
    /// engine of its routes and upstreams. The engine of the certificates is registered on its
    /// own, see [`Certificates::register`].
    pub fn register(self, services: &mut Services) {
        let listeners = HttpListeners::new(self.snapshot.clone(), self.conf, self.certificates);
        services.register(Protocol::Http, listeners);
        services.add_engine(Routing::new(self.snapshot));
    }
}
