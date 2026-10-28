//! A running service together with what is needed to drain it.

use std::sync::Arc;
use std::time::Duration;

use metrics::{Counter, Gauge};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};
use zora_core::config::Name;

use crate::service::{Connection, Service};
use crate::telemetry;

/// A service, the connections it serves and the signals that end them.
pub(crate) struct Host {
    /// Listener the service was built for, for logs.
    name: Name,
    /// The protocol service.
    service: Arc<dyn Service>,
    /// Turns `true` when draining starts.
    shutdown: watch::Sender<bool>,
    /// Tasks of the connections being served.
    connections: TaskTracker,
    /// Ends the connections that outlive the shutdown timeout.
    kill: CancellationToken,
    /// Counts the connections accepted for the listener.
    accepted: Counter,
    /// Tracks the connections open on the listener.
    active: Gauge,
}

impl Host {
    /// Wraps a newly built service.
    pub(crate) fn new(name: Name, service: Arc<dyn Service>) -> Self {
        let (accepted, active) = telemetry::connections(&name);
        Self {
            accepted,
            active,
            name,
            service,
            shutdown: watch::channel(false).0,
            connections: TaskTracker::new(),
            kill: CancellationToken::new(),
        }
    }

    /// Serves `conn` in a tracked task on the current runtime.
    pub(crate) fn spawn(&self, conn: Connection) {
        let serve = self.service.clone().serve(conn, self.shutdown.subscribe());
        let kill = self.kill.clone();
        let active = self.active.clone();
        self.accepted.increment(1);
        active.increment(1.0);
        self.connections.spawn(async move {
            // Dropping the service future closes the connection.
            tokio::select! {
                () = serve => {}
                () = kill.cancelled() => {}
            }
            active.decrement(1.0);
        });
    }

    /// Tells the service and its connections to finish. It returns at once; call
    /// [`Host::finish_drain`] to wait for them.
    pub(crate) fn begin_drain(&self) {
        info!(listener = %self.name, connections = self.connections.len(), "draining");
        // `send_replace` also updates the value when no connection is subscribed.
        self.shutdown.send_replace(true);
        self.connections.close();
    }

    /// Waits up to `timeout` for the connections to end after [`Host::begin_drain`], then
    /// closes the ones still open.
    pub(crate) async fn finish_drain(&self, timeout: Duration) {
        let finished = tokio::time::timeout(timeout, async {
            self.service.drain().await;
            self.connections.wait().await;
        })
        .await;
        if finished.is_err() {
            warn!(
                listener = %self.name,
                connections = self.connections.len(),
                "shutdown timeout reached, closing the remaining connections"
            );
            self.kill.cancel();
            self.connections.wait().await;
        }
        info!(listener = %self.name, "drained");
    }
}
