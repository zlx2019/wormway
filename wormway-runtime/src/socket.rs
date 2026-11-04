//! Listening sockets and their accept loops.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use socket2::{Domain, Protocol, Type};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use wormway_core::config::{Name, ServerSettings};

use crate::host::Host;
use crate::service::Connection;

/// How the listening sockets are opened, from the static settings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SocketOptions {
    /// Connections that the system holds for a socket until they are accepted.
    backlog: i32,
    /// Sockets per address: one per worker thread with `SO_REUSEPORT`, otherwise one.
    copies: usize,
}

impl SocketOptions {
    /// Takes the backlog and `reuseport` from `settings`, for a runtime with `workers` threads.
    /// `SO_REUSEPORT` spreads connections over the sockets only on Linux, so other systems get
    /// one socket per address.
    pub(crate) fn new(settings: &ServerSettings, workers: usize) -> Self {
        let copies = match (settings.reuseport, cfg!(target_os = "linux")) {
            (true, true) => {
                info!(
                    sockets = workers,
                    "reuseport: one socket per worker thread and address"
                );
                workers.max(1)
            }
            (true, false) => {
                warn!("reuseport works on Linux only, so every address gets one socket");
                1
            }
            (false, _) => 1,
        };
        Self {
            backlog: i32::try_from(settings.backlog.get()).unwrap_or(i32::MAX),
            copies,
        }
    }
}

/// Bound sockets of one address that do not accept connections yet.
pub(crate) struct Bound {
    /// Address from the configuration.
    configured: SocketAddr,
    /// Address actually bound, which differs for port 0.
    local: SocketAddr,
    /// The sockets, registered with the data-plane runtime.
    listeners: Vec<TcpListener>,
}

/// Binds `addr` as `options` say and registers the sockets with the runtime of `handle`.
pub(crate) fn bind(addr: SocketAddr, options: SocketOptions, handle: &Handle) -> io::Result<Bound> {
    let first = open(addr, options)?;
    let local = first.local_addr()?;
    let mut sockets = vec![first];
    // On the port the first one got, for port 0.
    for _ in 1..options.copies {
        sockets.push(open(local, options)?);
    }
    // Register with the data-plane runtime, not with the runtime applying the configuration.
    let _runtime = handle.enter();
    let listeners = sockets
        .into_iter()
        .map(TcpListener::from_std)
        .collect::<io::Result<_>>()?;
    Ok(Bound {
        configured: addr,
        local,
        listeners,
    })
}

/// Opens a non-blocking socket listening on `addr`. IPv6 sockets take IPv6 connections only, so
/// that the same port can listen on IPv4 too, and copies share the address through
/// `SO_REUSEPORT`.
fn open(addr: SocketAddr, options: SocketOptions) -> io::Result<std::net::TcpListener> {
    let socket =
        socket2::Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // As the standard library does on Unix: a restart can listen again right away, while
    // connections of the last run still wait out their close.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(target_os = "linux")]
    if options.copies > 1 {
        socket.set_reuse_port(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(options.backlog)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

impl Bound {
    /// Starts an accept loop per socket on `handle`. Connections go to `host` until the target
    /// changes.
    pub(crate) fn start(self, owner: Name, host: Arc<Host>, handle: &Handle) -> Socket {
        info!(listener = %owner, addr = %self.local, "listening");
        let target = Arc::new(ArcSwap::new(host));
        let stop = CancellationToken::new();
        for listener in self.listeners {
            handle.spawn(accept_loop(listener, target.clone(), stop.clone()));
        }
        Socket {
            owner,
            configured: self.configured,
            local: self.local,
            target,
            stop,
        }
    }
}

/// The listening sockets of one address, whose connections go to the current host of its
/// listener.
pub(crate) struct Socket {
    /// Listener the socket belongs to.
    pub(crate) owner: Name,
    /// Address from the configuration; port 0 asks for any free port.
    pub(crate) configured: SocketAddr,
    /// Address actually bound.
    pub(crate) local: SocketAddr,
    /// Host that new connections go to.
    pub(crate) target: Arc<ArcSwap<Host>>,
    /// Stops the accept loops, which close the sockets.
    stop: CancellationToken,
}

impl Socket {
    /// Stops accepting and closes the sockets. Open connections are not affected.
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    /// IPv6 sockets take IPv6 connections only, and every socket can listen again right after
    /// a restart.
    #[test]
    fn opens_ipv6_sockets_for_ipv6_only() {
        let options = SocketOptions {
            backlog: 16,
            copies: 1,
        };
        let v6 = socket2::Socket::from(open("[::1]:0".parse().unwrap(), options).unwrap());
        assert!(v6.only_v6().unwrap());
        assert!(v6.reuse_address().unwrap());
        let v4 = socket2::Socket::from(open("127.0.0.1:0".parse().unwrap(), options).unwrap());
        assert!(v4.reuse_address().unwrap());
    }

    /// reuseport asks for one socket per worker thread on Linux and for one elsewhere; without
    /// it every address gets one. Backlogs beyond what the system takes are capped.
    #[test]
    fn counts_sockets_per_address() {
        let mut settings = ServerSettings::default();
        assert_eq!(SocketOptions::new(&settings, 4).copies, 1);
        settings.reuseport = true;
        let expected = if cfg!(target_os = "linux") { 4 } else { 1 };
        assert_eq!(SocketOptions::new(&settings, 4).copies, expected);
        assert_eq!(SocketOptions::new(&settings, 4).backlog, 4096);
        settings.backlog = NonZeroU32::MAX;
        assert_eq!(SocketOptions::new(&settings, 4).backlog, i32::MAX);
    }
}
