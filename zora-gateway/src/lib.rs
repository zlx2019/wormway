//! The HTTP gateway of zora: serves the listeners with protocol `http` through Pingora and
//! routes their requests to upstreams.
//!
//! [`Gateway::register`] adds two parts to the [`Services`] of the runtime: the service factory
//! of protocol `http`, which gives every listener its own Pingora proxy, and an engine that
//! compiles the routes and upstreams of each configuration into a snapshot shared by all
//! listeners. Every request takes the snapshot in effect when it starts and keeps it until it
//! ends. Pingora types do not appear in the public API.

mod listener;
mod proxy;
mod snapshot;
mod upstream;

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora::server::configuration::ServerConf;
use zora_core::config::Protocol;
use zora_runtime::Services;

use crate::listener::HttpListeners;
use crate::snapshot::{GatewaySnapshot, Routing};

/// The HTTP gateway.
pub struct Gateway {
    /// Routes and upstreams in effect, shared by the listeners and the engine.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Pingora settings of every proxy.
    conf: Arc<ServerConf>,
}

impl Gateway {
    /// Creates a gateway for a data plane with `threads` worker threads. The number sizes the
    /// pools of idle upstream connections.
    pub fn new(threads: usize) -> Self {
        let conf = ServerConf {
            threads: threads.max(1),
            ..ServerConf::default()
        };
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(GatewaySnapshot::default())),
            conf: Arc::new(conf),
        }
    }

    /// Registers the gateway with `services`: the service factory of protocol `http` and the
    /// engine of its routes and upstreams.
    pub fn register(self, services: &mut Services) {
        services.register(
            Protocol::Http,
            HttpListeners::new(self.snapshot.clone(), self.conf),
        );
        services.add_engine(Routing::new(self.snapshot));
    }
}
