//! The server: runs the listeners of a configuration, switches to new configurations and shuts
//! down.

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::runtime::Handle;
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::task::TaskTracker;
use wormway_core::config::{Config, ConfigError, Listener, Name, Protocol};

use crate::engine::Staged;
use crate::health::UpstreamReport;
use crate::host::Host;
use crate::service::{BoxError, ServiceFactory, Services};
use crate::snapshot::Snapshot;
use crate::socket::{self, Bound, Socket};
use crate::telemetry;
use crate::tls::CertificateReport;

/// Runs the listeners of a configuration and switches to new configurations without dropping
/// connections.
pub struct Server {
    /// Runtime that accepts and serves the connections.
    handle: Handle,
    /// Service factories by protocol, and the engines.
    services: Services,
    /// How long connections may take to finish when their service drains.
    shutdown_timeout: Duration,
    /// The running listeners. Held from `prepare` to `commit`, so changes do not overlap.
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
    /// Set by `shutdown`; later changes are refused.
    closed: bool,
}

/// The changes of one switch, prepared without touching anything that runs.
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
    pub async fn start(
        handle: Handle,
        services: Services,
        config: Config,
    ) -> Result<Self, ApplyError> {
        telemetry::describe();
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
        server.apply(config).await?;
        Ok(server)
    }

    /// Checks that `config` could be applied: its validation rules hold and every protocol it
    /// uses is available. Engines are not prepared and addresses are not bound, so both can
    /// still fail later.
    pub fn validate(&self, config: &Config) -> Result<(), ApplyError> {
        config.validate().map_err(ConfigError::Invalid)?;
        for (name, listener) in &config.listeners {
            self.factory(name, listener.protocol)?;
        }
        Ok(())
    }

    /// Prepares the switch to `config`: validates it, prepares every engine, builds the services
    /// of new and changed listeners and binds the new addresses. Nothing running changes before
    /// [`Prepared::commit`], and dropping the result discards it. Other changes wait until
    /// then.
    pub async fn prepare(&self, config: Config) -> Result<Prepared<'_>, ApplyError> {
        let prepared = self.try_prepare(config).await;
        if prepared.is_err() {
            telemetry::config_applied(false);
        }
        prepared
    }

    /// Switches to `config` and returns its snapshot: [`Server::prepare`], then
    /// [`Prepared::commit`].
    ///
    /// Unchanged listeners keep running untouched. Changed and removed listeners drain: their
    /// old services are told so before this returns, and their open connections stay with them
    /// until they end or the shutdown timeout closes them. Addresses that stay keep their
    /// socket, so no connection is refused during the switch. On error nothing changes.
    ///
    /// Static settings keep the values given to [`Server::start`].
    pub async fn apply(&self, config: Config) -> Result<Arc<Snapshot>, ApplyError> {
        Ok(self.prepare(config).await?.commit())
    }

    /// Applies the configuration in effect again, so that engines read their sources again,
    /// such as certificate files. Listeners whose settings did not change keep running
    /// untouched. A change that another caller commits meanwhile is kept, not undone.
    pub async fn reapply(&self) -> Result<Arc<Snapshot>, ApplyError> {
        let state = self.state.lock().await;
        // Read under the lock, so that it is the newest configuration.
        let config = self.snapshot.load().config.clone();
        let prepared = self.prepare_locked(state, config).await;
        if prepared.is_err() {
            telemetry::config_applied(false);
        }
        Ok(prepared?.commit())
    }

    /// Returns the configuration in effect.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }

    /// Returns the bound addresses of every listener.
    pub async fn listeners(&self) -> BTreeMap<Name, Vec<SocketAddr>> {
        let state = self.state.lock().await;
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

    /// Returns the upstreams in effect with the health of their targets; none without a health
    /// report.
    pub fn upstreams(&self) -> Vec<UpstreamReport> {
        self.services
            .health_report()
            .map(|report| report.upstreams())
            .unwrap_or_default()
    }

    /// Returns the certificates in effect; none without a certificate report.
    pub fn certificates(&self) -> Vec<CertificateReport> {
        self.services
            .tls_report()
            .map(|report| report.certificates())
            .unwrap_or_default()
    }

    /// Stops accepting on every listener and drains every service. Connections still open when
    /// the shutdown timeout ends are closed. Later changes are refused.
    pub async fn shutdown(&self) {
        {
            let mut state = self.state.lock().await;
            state.closed = true;
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

    /// Validates `config` and plans the switch to it while holding the state.
    async fn try_prepare(&self, config: Config) -> Result<Prepared<'_>, ApplyError> {
        self.validate(&config)?;
        let state = self.state.lock().await;
        self.prepare_locked(state, config).await
    }

    /// Prepares the engines and plans the switch to `config` with the state already held.
    async fn prepare_locked<'a>(
        &'a self,
        state: MutexGuard<'a, State>,
        config: Config,
    ) -> Result<Prepared<'a>, ApplyError> {
        if state.closed {
            return Err(ApplyError::ShuttingDown);
        }
        let staged = self.prepare_engines(&config).await?;
        let plan = self.plan(&state, &config.listeners)?;
        Ok(Prepared {
            server: self,
            state,
            staged,
            plan,
            config,
        })
    }

    /// Prepares every engine for `config`, in order. The problems of all of them are reported
    /// together.
    async fn prepare_engines(&self, config: &Config) -> Result<Vec<Box<dyn Staged>>, ApplyError> {
        let mut staged = Vec::with_capacity(self.services.engines().len());
        let mut issues = Vec::new();
        for engine in self.services.engines() {
            match engine.prepare(config).await {
                Ok(state) => staged.push(state),
                Err(problems) => issues.extend(problems),
            }
        }
        if issues.is_empty() {
            Ok(staged)
        } else {
            Err(ConfigError::Invalid(issues).into())
        }
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

    /// Returns the service factory for `protocol`, which listener `name` uses.
    fn factory(
        &self,
        name: &Name,
        protocol: Protocol,
    ) -> Result<&Arc<dyn ServiceFactory>, ApplyError> {
        self.services
            .get(protocol)
            .ok_or_else(|| ApplyError::Unsupported {
                listener: name.clone(),
                protocol,
            })
    }

    /// Builds the service of `listener` with the factory of its protocol.
    fn new_host(&self, name: &Name, listener: &Listener) -> Result<Host, ApplyError> {
        let service = self
            .factory(name, listener.protocol)?
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
        for socket in &self.state.get_mut().sockets {
            socket.close();
        }
    }
}

// The Admin API shares the server with the signal handling, across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Server>();
};

/// A configuration ready to switch to, from [`Server::prepare`]. Nothing running has changed
/// yet: dropping it discards the new services and sockets.
pub struct Prepared<'a> {
    /// The server to switch.
    server: &'a Server,
    /// Keeps other changes out until this one is committed or dropped.
    state: MutexGuard<'a, State>,
    /// State of every engine, in the order of the engines.
    staged: Vec<Box<dyn Staged>>,
    /// What to change.
    plan: Plan,
    /// The configuration to switch to.
    config: Config,
}

impl Prepared<'_> {
    /// Switches to the configuration and returns its snapshot. It cannot fail.
    ///
    /// Engines commit first, so that new listeners find their state when they start accepting.
    pub fn commit(self) -> Arc<Snapshot> {
        let Self {
            server,
            mut state,
            staged,
            plan,
            config,
        } = self;
        for engine in staged {
            engine.commit();
        }
        let snapshot = Arc::new(Snapshot {
            version: server.snapshot.load().version + 1,
            config,
        });
        server.snapshot.store(snapshot.clone());
        server.commit(&mut state, plan);
        telemetry::config_applied(true);
        snapshot
    }
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
    /// The server is shutting down and takes no more changes.
    #[error("the server is shutting down")]
    ShuttingDown,
}
