//! The server: runs the listeners of a configuration, switches to new configurations and shuts
//! down.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::runtime::Handle;
use tokio_util::task::TaskTracker;
use zora_core::config::{Config, ConfigError, Listener, Name, Protocol};

use crate::host::Host;
use crate::service::{BoxError, Services};
use crate::snapshot::Snapshot;
use crate::socket::{self, Bound, Socket};

/// Runs the listeners of a configuration and switches to new configurations without dropping
/// connections.
pub struct Server {
    /// Runtime that accepts and serves the connections.
    handle: Handle,
    /// Service factories by protocol.
    services: Services,
    /// How long connections may take to finish when their service drains.
    shutdown_timeout: Duration,
    /// The running listeners. Held while a configuration is applied, so applies do not overlap.
    state: Mutex<State>,
    /// The configuration in effect.
    snapshot: ArcSwap<Snapshot>,
    /// Drains of services that are no longer used.
    draining: TaskTracker,
}

/// The running listeners.
#[derive(Default)]
struct State {
    /// Services by listener name, with the settings they were built from.
    hosts: BTreeMap<Name, (Listener, Arc<Host>)>,
    /// Sockets of all listeners, in listener order.
    sockets: Vec<Socket>,
}

/// The changes of one apply, prepared without touching anything that runs.
struct Plan {
    /// Services of the new configuration: reused ones for unchanged listeners, new ones for the
    /// others.
    hosts: BTreeMap<Name, (Listener, Arc<Host>)>,
    /// The socket of every address in the new configuration, with its listener.
    sockets: Vec<(Name, Planned)>,
}

/// Where the socket of one address comes from.
enum Planned {
    /// The running socket at this index of `State::sockets` keeps accepting.
    Kept(usize),
    /// A new socket.
    New(Bound),
}

impl Server {
    /// Starts serving `config` with connections handled on the runtime of `handle`.
    pub fn start(handle: Handle, services: Services, config: Config) -> Result<Self, ApplyError> {
        let server = Self {
            handle,
            services,
            shutdown_timeout: config.server.shutdown_timeout.get(),
            state: Mutex::default(),
            // Replaced by the first apply below before anyone can see it.
            snapshot: ArcSwap::from_pointee(Snapshot {
                version: 0,
                config: config.clone(),
            }),
            draining: TaskTracker::new(),
        };
        server.apply(config)?;
        Ok(server)
    }

    /// Switches to `config` and returns its snapshot.
    ///
    /// Unchanged listeners keep running untouched. Changed and removed listeners drain: their
    /// old services are told so before this returns, and their open connections stay with them
    /// until they end or the shutdown timeout closes them. Addresses that stay keep their
    /// socket, so no connection is refused during the switch. On error nothing changes.
    ///
    /// Static settings keep the values given to [`Server::start`].
    pub fn apply(&self, config: Config) -> Result<Arc<Snapshot>, ApplyError> {
        config.validate().map_err(ConfigError::Invalid)?;
        let mut state = lock(&self.state);
        let plan = self.plan(&state, &config.listeners)?;
        let snapshot = Arc::new(Snapshot {
            version: self.snapshot.load().version + 1,
            config,
        });
        self.snapshot.store(snapshot.clone());
        self.commit(&mut state, plan);
        Ok(snapshot)
    }

    /// Returns the configuration in effect.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    /// Returns the bound addresses of every listener.
    pub fn listeners(&self) -> BTreeMap<Name, Vec<SocketAddr>> {
        let state = lock(&self.state);
        let mut listeners: BTreeMap<Name, Vec<SocketAddr>> = state
            .hosts
            .keys()
            .map(|name| (name.clone(), Vec::new()))
            .collect();
        for socket in &state.sockets {
            if let Some(addrs) = listeners.get_mut(&socket.owner) {
                addrs.push(socket.local);
            }
        }
        listeners
    }

    /// Stops accepting on every listener and drains every service. Connections still open when
    /// the shutdown timeout ends are closed. Do not apply configurations afterwards.
    pub async fn shutdown(&self) {
        {
            let mut state = lock(&self.state);
            for socket in state.sockets.drain(..) {
                socket.close();
            }
            for (_, host) in std::mem::take(&mut state.hosts).into_values() {
                self.retire(host);
            }
        }
        self.draining.close();
        self.draining.wait().await;
    }

    /// Builds the services and binds the sockets that `listeners` needs. Running listeners are
    /// not touched, so an error leaves everything as it was.
    fn plan(
        &self,
        state: &State,
        listeners: &BTreeMap<Name, Listener>,
    ) -> Result<Plan, ApplyError> {
        let mut hosts = BTreeMap::new();
        for (name, listener) in listeners {
            let host = match state.hosts.get(name) {
                Some((running, host)) if running == listener => host.clone(),
                _ => Arc::new(self.new_host(name, listener)?),
            };
            hosts.insert(name.clone(), (listener.clone(), host));
        }

        let mut kept = vec![false; state.sockets.len()];
        let mut sockets = Vec::new();
        for (name, (listener, host)) in &hosts {
            for &addr in &listener.listen {
                // A fixed port keeps its socket whichever listener takes it over. Port 0 binds
                // any free port, so its socket is kept only for the same, unchanged service.
                let reusable = |&(i, socket): &(usize, &Socket)| {
                    !kept[i]
                        && socket.configured == addr
                        && (addr.port() != 0 || Arc::ptr_eq(&socket.target.load(), host))
                };
                let planned = match state.sockets.iter().enumerate().find(reusable) {
                    Some((i, _)) => {
                        kept[i] = true;
                        Planned::Kept(i)
                    }
                    None => Planned::New(socket::bind(addr, &self.handle).map_err(|source| {
                        ApplyError::Bind {
                            listener: name.clone(),
                            addr,
                            source,
                        }
                    })?),
                };
                sockets.push((name.clone(), planned));
            }
        }
        Ok(Plan { hosts, sockets })
    }

    /// Builds the service of `listener` with the factory of its protocol.
    fn new_host(&self, name: &Name, listener: &Listener) -> Result<Host, ApplyError> {
        let factory =
            self.services
                .get(listener.protocol)
                .ok_or_else(|| ApplyError::Unsupported {
                    listener: name.clone(),
                    protocol: listener.protocol,
                })?;
        let service = factory
            .create(name, listener)
            .map_err(|source| ApplyError::Service {
                listener: name.clone(),
                source,
            })?;
        Ok(Host::new(name.clone(), service))
    }

    /// Switches the running listeners over to `plan`. Everything that can fail happened in
    /// [`Server::plan`].
    fn commit(&self, state: &mut State, plan: Plan) {
        let mut current: Vec<Option<Socket>> = state.sockets.drain(..).map(Some).collect();
        let mut sockets = Vec::with_capacity(plan.sockets.len());
        for (owner, planned) in plan.sockets {
            let host = plan.hosts[&owner].1.clone();
            match planned {
                Planned::Kept(i) => {
                    if let Some(mut socket) = current[i].take() {
                        socket.owner = owner;
                        socket.target.store(host);
                        sockets.push(socket);
                    }
                }
                Planned::New(bound) => sockets.push(bound.start(owner, host, &self.handle)),
            }
        }
        // Sockets that no listener kept.
        for socket in current.into_iter().flatten() {
            socket.close();
        }
        // Services that no listener uses any more.
        let old = std::mem::replace(&mut state.hosts, plan.hosts);
        for (_, host) in old.into_values() {
            if !state
                .hosts
                .values()
                .any(|(_, kept)| Arc::ptr_eq(kept, &host))
            {
                self.retire(host);
            }
        }
        state.sockets = sockets;
    }

    /// Tells `host` to drain right away, so that it knows once the caller returns, and waits for
    /// its connections in the background.
    fn retire(&self, host: Arc<Host>) {
        host.begin_drain();
        let timeout = self.shutdown_timeout;
        self.draining.spawn_on(
            async move { host.finish_drain(timeout).await },
            &self.handle,
        );
    }
}

impl Drop for Server {
    /// Stops accepting if [`Server::shutdown`] was not called. Open connections keep running
    /// until they end or their runtime shuts down.
    fn drop(&mut self) {
        for socket in &lock(&self.state).sockets {
            socket.close();
        }
    }
}

// The Admin API shares the server with the signal handling, across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Server>();
};

/// Locks `mutex` even if a panic poisoned it. The state stays consistent: `plan`, which runs
/// the service factories, does not modify it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why a configuration could not be applied. The configuration in effect stays.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The configuration breaks validation rules.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// No service factory is registered for the protocol of a listener.
    #[error("listener {listener}: protocol {protocol} is not available in this build")]
    Unsupported {
        /// The listener.
        listener: Name,
        /// Its protocol.
        protocol: Protocol,
    },
    /// The service factory of a listener failed.
    #[error("listener {listener}: cannot create the service")]
    Service {
        /// The listener.
        listener: Name,
        /// Why the factory failed.
        #[source]
        source: BoxError,
    },
    /// An address could not be bound.
    #[error("listener {listener}: cannot listen on {addr}")]
    Bind {
        /// The listener.
        listener: Name,
        /// The address.
        addr: SocketAddr,
        /// Why binding failed.
        #[source]
        source: io::Error,
    },
}
