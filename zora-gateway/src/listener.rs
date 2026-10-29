//! The HTTP listeners: each one gets its own Pingora proxy, so that it can drain on its own.

use std::any::Any;
use std::os::unix::io::AsRawFd;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use pingora::apps::{HttpServerApp, HttpServerOptions, ServerApp};
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora::proxy::{HttpProxy, http_proxy};
use pingora::server::configuration::ServerConf;
use zora_core::config::{Listener, Name};
use zora_runtime::{BoxError, BoxFuture, Connection, Service, ServiceFactory, Shutdown};

use crate::proxy::Proxy;
use crate::snapshot::GatewaySnapshot;

/// Builds the service of each HTTP listener.
pub(crate) struct HttpListeners {
    /// Routes and upstreams in effect, shared by every listener.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Pingora settings of every proxy.
    conf: Arc<ServerConf>,
}

impl HttpListeners {
    /// Creates the factory.
    pub(crate) fn new(snapshot: Arc<ArcSwap<GatewaySnapshot>>, conf: Arc<ServerConf>) -> Self {
        Self { snapshot, conf }
    }
}

impl ServiceFactory for HttpListeners {
    /// Builds a Pingora proxy with the HTTP settings of the listener.
    fn create(&self, name: &Name, listener: &Listener) -> Result<Arc<dyn Service>, BoxError> {
        if listener.tls.is_some() {
            return Err("TLS listeners are not available yet".into());
        }
        let keepalive = KeepAlive::new(listener.http.keepalive_timeout().get());
        let app = Proxy::new(name.clone(), self.snapshot.clone(), keepalive.http1);
        // Pingora loads the system root certificates for its upstream connector here, and
        // panics when that fails, for example when SSL_CERT_FILE names a missing file.
        let mut proxy = panic::catch_unwind(AssertUnwindSafe(|| http_proxy(&self.conf, app)))
            .map_err(|payload| {
                format!(
                    "cannot load the system root certificates for upstream TLS, check \
                     SSL_CERT_FILE and SSL_CERT_DIR: {}",
                    panic_message(&*payload)
                )
            })?;
        let mut options = HttpServerOptions::default();
        options.h2_idle_timeout = Some(keepalive.http2);
        proxy.server_options = Some(options);
        Ok(Arc::new(HttpService {
            proxy: Arc::new(proxy),
        }))
    }
}

/// Returns the message of a panic payload.
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    match payload.downcast_ref::<String>() {
        Some(message) => message,
        None => payload
            .downcast_ref::<&str>()
            .copied()
            .unwrap_or("unknown panic"),
    }
}

/// Keep-alive limits of a listener, from its `keepalive_timeout`.
struct KeepAlive {
    /// Seconds an HTTP/1.1 connection waits for its next request; `None` turns keep-alive off.
    http1: Option<u64>,
    /// How long an HTTP/2 connection may stay without requests.
    http2: Duration,
}

impl KeepAlive {
    /// Derives the limits from `timeout`, rounded up to whole seconds as Pingora counts them for
    /// HTTP/1.1. HTTP/2 connections cannot turn keep-alive off, and with no time at all they
    /// would close before their first request, so they get at least a second.
    fn new(timeout: Duration) -> Self {
        let secs = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
        Self {
            http1: (secs > 0).then_some(secs),
            http2: Duration::from_secs(secs.max(1)),
        }
    }
}

/// Serves the connections of one HTTP listener with its own Pingora proxy.
struct HttpService {
    /// The proxy.
    proxy: Arc<HttpProxy<Proxy>>,
}

impl Service for HttpService {
    /// Serves HTTP/1.1, with keep-alive, or HTTP/2 until the connection ends.
    fn serve(self: Arc<Self>, conn: Connection, shutdown: Shutdown) -> BoxFuture<'static> {
        Box::pin(async move {
            // Pingora serves every request of the connection in this call and returns nothing
            // for HTTP.
            let _ = self
                .proxy
                .process_new(pingora_stream(conn), &shutdown)
                .await;
        })
    }

    /// Wakes the connections that wait for their next request, so that they close now. The
    /// proxy stays closed afterwards, which is why every listener has its own.
    fn drain(&self) -> BoxFuture<'_> {
        self.proxy.http_cleanup()
    }
}

/// Turns an accepted connection into a Pingora stream that knows the address of its client.
fn pingora_stream(conn: Connection) -> Stream {
    let mut stream = L4Stream::from(conn.stream);
    // The same digest as Pingora's own listeners set up, so that `client_addr()` works.
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    let _ = digest.peer_addr.set(Some(conn.peer.into()));
    stream.set_socket_digest(digest);
    Box::new(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Timeouts round up to whole seconds; zero turns HTTP/1.1 keep-alive off and leaves
    /// HTTP/2 one second.
    #[test]
    fn derives_keepalive_limits() {
        let limits = |millis| {
            let keepalive = KeepAlive::new(Duration::from_millis(millis));
            (keepalive.http1, keepalive.http2.as_secs())
        };
        assert_eq!(limits(75_000), (Some(75), 75));
        assert_eq!(limits(1_500), (Some(2), 2));
        assert_eq!(limits(1), (Some(1), 1));
        assert_eq!(limits(0), (None, 1));
    }
}
