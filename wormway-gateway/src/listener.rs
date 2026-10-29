//! The HTTP listeners: each one gets its own Pingora proxy, so that it can drain on its own, and
//! listeners with TLS their own TLS settings.

use std::any::Any;
use std::os::unix::io::AsRawFd;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use pingora::apps::{HttpServerApp, HttpServerOptions, ServerApp};
use pingora::listeners::tls::Acceptor;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora::proxy::{HttpProxy, http_proxy};
use pingora::server::configuration::ServerConf;
use tokio::io::AsyncReadExt;
use tracing::debug;
use wormway_core::config::{Listener, Name};
use wormway_runtime::{BoxError, BoxFuture, Connection, Service, ServiceFactory, Shutdown};
use wormway_tls::Certificates;

use crate::proxy::Proxy;
use crate::snapshot::GatewaySnapshot;

/// Application protocols that listeners with TLS offer, in order of preference.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];
/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Length of the bytes that HTTP/2 without TLS starts with, which Pingora reads to tell it from
/// HTTP/1.1 on listeners with h2c.
const PREFACE_LEN: usize = 24;
/// How long a client of a listener with h2c may take to send those bytes: as long as Pingora
/// allows for the headers of an HTTP/1.1 request. Pingora itself waits for them without a limit.
const PREFACE_TIMEOUT: Duration = Duration::from_secs(60);

/// Builds the service of each HTTP listener.
pub(crate) struct HttpListeners {
    /// Routes and upstreams in effect, shared by every listener.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Pingora settings of every proxy.
    conf: Arc<ServerConf>,
    /// Certificates of the listeners with TLS.
    certificates: Certificates,
}

impl HttpListeners {
    /// Creates the factory.
    pub(crate) fn new(
        snapshot: Arc<ArcSwap<GatewaySnapshot>>,
        conf: Arc<ServerConf>,
        certificates: Certificates,
    ) -> Self {
        Self {
            snapshot,
            conf,
            certificates,
        }
    }
}

impl ServiceFactory for HttpListeners {
    /// Builds a Pingora proxy with the HTTP settings of the listener, and its TLS settings if it
    /// has TLS.
    fn create(&self, name: &Name, listener: &Listener) -> Result<Arc<dyn Service>, BoxError> {
        let tls = match listener.tls {
            Some(_) => {
                let config = self.certificates.server_config(name, &ALPN)?;
                Some(Acceptor::from_server_config(config))
            }
            None => None,
        };
        let keepalive = KeepAlive::new(listener.http.keepalive_timeout().get());
        let app = Proxy::new(
            name.clone(),
            self.snapshot.clone(),
            keepalive.http1,
            listener.tls.is_some(),
        );
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
        // Pingora ignores h2c on TLS connections, which agree on HTTP/2 through ALPN.
        options.h2c = listener.http.h2c();
        options.h2_idle_timeout = Some(keepalive.http2);
        proxy.server_options = Some(options);
        Ok(Arc::new(HttpService {
            proxy: Arc::new(proxy),
            h2c: tls.is_none() && listener.http.h2c(),
            tls,
        }))
    }
}

/// Returns the message of a panic payload.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> &str {
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
    /// The TLS handshake of a listener with TLS.
    tls: Option<Acceptor>,
    /// Whether the listener accepts HTTP/2 without TLS.
    h2c: bool,
}

impl Service for HttpService {
    /// Completes the TLS handshake if the listener has TLS, or waits for the start of the
    /// request if it accepts HTTP/2 without TLS, then serves HTTP/1.1, with keep-alive, or HTTP/2
    /// until the connection ends.
    fn serve(self: Arc<Self>, conn: Connection, shutdown: Shutdown) -> BoxFuture<'static> {
        Box::pin(async move {
            let peer = conn.peer;
            let stream = l4_stream(conn);
            let stream: Stream = match &self.tls {
                None if self.h2c => match read_preface(stream, PREFACE_TIMEOUT).await {
                    Some(stream) => Box::new(stream),
                    None => {
                        debug!(%peer, "no request started in time");
                        return;
                    }
                },
                None => Box::new(stream),
                Some(acceptor) => {
                    let handshake = acceptor.tls_handshake(stream);
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                        Ok(Ok(tls)) => Box::new(tls),
                        Ok(Err(error)) => {
                            debug!(%peer, %error, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            debug!(%peer, "TLS handshake timed out");
                            return;
                        }
                    }
                }
            };
            // Pingora serves every request of the connection in this call and returns nothing
            // for HTTP.
            let _ = self.proxy.process_new(stream, &shutdown).await;
        })
    }

    /// Wakes the connections that wait for their next request, so that they close now. The
    /// proxy stays closed afterwards, which is why every listener has its own.
    fn drain(&self) -> BoxFuture<'_> {
        self.proxy.http_cleanup()
    }
}

/// Reads the first bytes of a connection, from which Pingora tells HTTP/2 from HTTP/1.1, within
/// `limit`, and puts them back for Pingora to read. Returns `None` if the client sends fewer in
/// time or closes the connection first.
async fn read_preface(mut stream: L4Stream, limit: Duration) -> Option<L4Stream> {
    let mut preface = [0; PREFACE_LEN];
    match tokio::time::timeout(limit, stream.read_exact(&mut preface)).await {
        Ok(Ok(_)) => {
            stream.rewind(&preface);
            Some(stream)
        }
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Turns an accepted connection into a Pingora stream that knows the address of its client.
fn l4_stream(conn: Connection) -> L4Stream {
    let mut stream = L4Stream::from(conn.stream);
    // The same digest as Pingora's own listeners set up, so that `client_addr()` works.
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    let _ = digest.peer_addr.set(Some(conn.peer.into()));
    stream.set_socket_digest(digest);
    stream
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first bytes come back for Pingora to read, and a client that sends too few in time
    /// is let go.
    #[tokio::test]
    async fn waits_for_the_preface_within_a_limit() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request = b"GET /a/long/enough/path HTTP/1.1\r\n";
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut stream = read_preface(L4Stream::from(server), Duration::from_secs(5))
            .await
            .expect("enough bytes");
        let mut read = vec![0; request.len()];
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(read, request);

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let short = read_preface(L4Stream::from(server), Duration::from_millis(100)).await;
        assert!(short.is_none());
    }

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
