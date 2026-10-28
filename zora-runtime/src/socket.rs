//! Listening sockets and their accept loops.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zora_core::config::Name;

use crate::host::Host;
use crate::service::Connection;

/// A bound socket that does not accept connections yet.
pub(crate) struct Bound {
    /// Address from the configuration.
    configured: SocketAddr,
    /// Address actually bound, which differs for port 0.
    local: SocketAddr,
    /// The socket, registered with the data-plane runtime.
    listener: TcpListener,
}

/// Binds `addr` and registers the socket with the runtime of `handle`.
pub(crate) fn bind(addr: SocketAddr, handle: &Handle) -> io::Result<Bound> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;
    // Register with the data-plane runtime, not with the runtime applying the configuration.
    let _runtime = handle.enter();
    Ok(Bound {
        configured: addr,
        local,
        listener: TcpListener::from_std(listener)?,
    })
}

impl Bound {
    /// Starts the accept loop on `handle`. Connections go to `host` until the target changes.
    pub(crate) fn start(self, owner: Name, host: Arc<Host>, handle: &Handle) -> Socket {
        info!(listener = %owner, addr = %self.local, "listening");
        let target = Arc::new(ArcSwap::new(host));
        let stop = CancellationToken::new();
        handle.spawn(accept_loop(self.listener, target.clone(), stop.clone()));
        Socket {
            owner,
            configured: self.configured,
            local: self.local,
            target,
            stop,
        }
    }
}

/// A listening socket whose connections go to the current host of its listener.
pub(crate) struct Socket {
    /// Listener the socket belongs to.
    pub(crate) owner: Name,
    /// Address from the configuration; port 0 asks for any free port.
    pub(crate) configured: SocketAddr,
    /// Address actually bound.
    pub(crate) local: SocketAddr,
    /// Host that new connections go to.
    pub(crate) target: Arc<ArcSwap<Host>>,
    /// Stops the accept loop, which closes the socket.
    stop: CancellationToken,
}

impl Socket {
    /// Stops accepting and closes the socket. Open connections are not affected.
    pub(crate) fn close(&self) {
        info!(listener = %self.owner, addr = %self.local, "stopped listening");
        self.stop.cancel();
    }
}

/// Accepts connections until `stop` is cancelled, then drops the socket.
async fn accept_loop(listener: TcpListener, target: Arc<ArcSwap<Host>>, stop: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                // Proxied traffic is latency sensitive, so do not hold back small writes.
                if let Err(error) = stream.set_nodelay(true) {
                    warn!(%error, %peer, "cannot disable Nagle's algorithm");
                }
                target.load().spawn(Connection { stream, peer });
            }
            Err(error) => pause_after(error).await,
        }
    }
}

/// Handles a failed accept. Errors of a single connection are skipped. Others, such as running
/// out of file descriptors, pause accepting briefly instead of retrying in a busy loop.
async fn pause_after(error: io::Error) {
    use io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset, Interrupted};
    if matches!(
        error.kind(),
        ConnectionAborted | ConnectionRefused | ConnectionReset | Interrupted
    ) {
        return;
    }
    warn!(%error, "accept failed, pausing for 100 ms");
    tokio::time::sleep(Duration::from_millis(100)).await;
}
