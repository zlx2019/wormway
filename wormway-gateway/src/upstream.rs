//! Upstreams at run time: a load balancer over the targets of each upstream, with host names
//! resolved again in the background, and the settings that every request to it follows.

use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::selection::{BackendIter, BackendSelection, Consistent, Random, RoundRobin};
use pingora::lb::{Backend, Backends, LoadBalancer};
use pingora::protocols::l4::socket::SocketAddr as PeerAddr;
use pingora::protocols::tls::ALPN;
use pingora::upstreams::peer::HttpPeer;
use wormway_core::config::{
    Balance, HashKey, Name, RouteTimeouts, Target, TargetAddress, Timeouts, Upstream,
    UpstreamProtocol,
};

use crate::health::{UpstreamHealth, Watch};
use crate::upstream_tls::PeerTls;

/// How many targets a selection may look at before it gives up.
const SELECT_ATTEMPTS: usize = 16;
/// Longest wait for the addresses of a host name.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the host names of an upstream are resolved again.
const RESOLVE_INTERVAL: Duration = Duration::from_secs(30);
/// Requests that share one HTTP/2 connection to a target at the same time; Pingora allows one.
const H2_STREAMS: usize = 100;

/// An upstream as the routes of one snapshot use it: the shared runtime and the settings of
/// this configuration.
pub(crate) struct CompiledUpstream {
    /// The load balancer, shared with the snapshots whose targets, balancing and health checks
    /// are the same.
    pub(crate) runtime: Arc<UpstreamRuntime>,
    /// What consistent hashing hashes, for upstreams that balance that way.
    hash_key: Option<HashKey>,
    /// Time limits of the connections and requests.
    timeouts: Timeouts,
    /// How many other targets a request tries when it cannot connect.
    retries: u32,
    /// How requests reach the targets.
    connect: Arc<Connect>,
}

impl CompiledUpstream {
    /// Puts the settings of `upstream` on `runtime`, reaching the targets through `connect`.
    pub(crate) fn new(
        runtime: Arc<UpstreamRuntime>,
        upstream: &Upstream,
        connect: Arc<Connect>,
    ) -> Self {
        Self {
            runtime,
            hash_key: (upstream.balance() == Balance::ConsistentHash).then(|| upstream.hash_key()),
            timeouts: upstream.timeouts,
            retries: upstream.retries(),
            connect,
        }
    }

    /// Hands the way to reach the targets to the health checks; called when the snapshot goes
    /// into effect, so that a change that is turned down never reaches them.
    pub(crate) fn publish(&self) {
        if let Some(health) = self.runtime.health() {
            health.reach(self.connect.clone());
        }
    }

    /// Returns what consistent hashing hashes, or `None` if the upstream balances otherwise.
    pub(crate) fn hash_key(&self) -> Option<&HashKey> {
        self.hash_key.as_ref()
    }

    /// Returns how many other targets a request tries when it cannot connect.
    pub(crate) fn retries(&self) -> u32 {
        self.retries
    }

    /// Returns the peer that sends a request of a route with time limits `route` to `target`.
    pub(crate) fn peer(&self, target: &Backend, route: &RouteTimeouts) -> HttpPeer {
        let mut peer = self.connect.peer(target);
        let options = &mut peer.options;
        options.total_connection_timeout = Some(self.timeouts.connect().get());
        options.read_timeout = Some(route.read.unwrap_or(self.timeouts.read()).get());
        options.write_timeout = Some(route.write.unwrap_or(self.timeouts.write()).get());
        options.idle_timeout = Some(self.timeouts.idle().get());
        peer
    }
}

/// How requests and health checks reach the targets of an upstream: the protocol and TLS.
pub(crate) struct Connect {
    /// The protocol spoken with the targets.
    protocol: UpstreamProtocol,
    /// TLS to the targets, if any.
    tls: Option<PeerTls>,
}

impl Connect {
    /// Reaches the targets with `protocol`, over `tls` if set.
    pub(crate) fn new(protocol: UpstreamProtocol, tls: Option<PeerTls>) -> Self {
        Self { protocol, tls }
    }

    /// Returns a peer that reaches `target`, without time limits.
    pub(crate) fn peer(&self, target: &Backend) -> HttpPeer {
        let sni = self
            .tls
            .as_ref()
            .map(|tls| tls.sni(target))
            .unwrap_or_default();
        let mut peer = HttpPeer::new(target.clone(), false, sni);
        if let Some(tls) = &self.tls {
            tls.configure(&mut peer);
        }
        // HTTP/2 only: over TLS through ALPN, without TLS from the first byte.
        if matches!(self.protocol, UpstreamProtocol::H2 | UpstreamProtocol::H2c) {
            peer.options.alpn = ALPN::H2;
            peer.options.max_h2_streams = H2_STREAMS;
        }
        peer
    }

    /// Whether the targets are reached over TLS.
    pub(crate) fn tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Returns the configured name that TLS sends to every target, if any.
    pub(crate) fn sni(&self) -> Option<&str> {
        self.tls.as_ref().and_then(PeerTls::name)
    }
}

/// The load balancer of an upstream and the targets it balances over.
///
/// A new configuration reuses the runtime of an upstream whose targets, balancing and health
/// checks did not change, so its state, such as the position of the round robin and the
/// requests in progress, carries over. The health of the targets carries over to a new runtime
/// as long as the health checks stay the same.
pub(crate) struct UpstreamRuntime {
    /// The upstream, for the log.
    name: Name,
    /// Targets the runtime was built from.
    targets: Vec<Target>,
    /// Balancing the runtime was built from.
    balance: Balance,
    /// The targets with host names resolved, which the load balancer reads on every update.
    resolved: Arc<ArcSwap<BTreeSet<Backend>>>,
    /// Picks the target of each request.
    balancer: Balancer,
    /// The targets as registered with the health of the upstream; `None` without health
    /// checks.
    watch: Option<Watch>,
    /// Where the next search through every target starts, for requests without a key.
    turn: AtomicUsize,
}

impl UpstreamRuntime {
    /// Builds the runtime of upstream `name` with `settings`, after resolving its host names.
    /// With `health`, targets that were never probed are probed through `connect` first. The
    /// problems come with the index of their target. With host names, a task resolves them
    /// again every 30 seconds until the runtime is dropped.
    pub(crate) async fn new(
        name: &Name,
        settings: &Upstream,
        health: Option<Arc<UpstreamHealth>>,
        connect: &Arc<Connect>,
    ) -> Result<Arc<Self>, Vec<(usize, String)>> {
        let targets = resolve(&settings.targets).await?;
        let watch = health.map(|health| health.watch());
        if let Some(watch) = &watch {
            let unprobed = watch.update(&targets);
            watch.health().probe(unprobed, connect.clone()).await;
        }
        let resolved = Arc::new(ArcSwap::from_pointee(targets));
        let backends = Backends::new(Box::new(Resolved(resolved.clone())));
        let runtime = Arc::new(Self {
            name: name.clone(),
            targets: settings.targets.clone(),
            balance: settings.balance(),
            resolved,
            balancer: Balancer::new(settings.balance(), backends),
            watch,
            turn: AtomicUsize::new(0),
        });
        // Reads the resolved targets; it does not wait for anything.
        if let Err(error) = runtime.balancer.update().await {
            return Err(vec![(0, error.to_string())]);
        }
        let names = settings
            .targets
            .iter()
            .any(|target| matches!(target.address, TargetAddress::Name { .. }));
        if names {
            tokio::spawn(keep_resolving(Arc::downgrade(&runtime)));
        }
        Ok(runtime)
    }

    /// Whether the runtime balances over the targets of `settings` in its way, and checks their
    /// health as `settings` asks.
    pub(crate) fn serves(&self, settings: &Upstream) -> bool {
        let checks = match self.health() {
            Some(health) => health.checks_as(settings),
            None => settings.health_check.is_none() && settings.passive.is_none(),
        };
        self.targets == settings.targets && self.balance == settings.balance() && checks
    }

    /// Returns the health of the targets, for upstreams with health checks.
    pub(crate) fn health(&self) -> Option<&Arc<UpstreamHealth>> {
        self.watch.as_ref().map(Watch::health)
    }

    /// Picks a healthy target that `accept` takes, for a request with consistent-hashing key
    /// `key`. When only targets that the passive checks took out are left, they are picked
    /// anyway, as in Nginx: an upstream with one target keeps it.
    pub(crate) fn select(&self, key: &[u8], accept: impl Fn(&Backend) -> bool) -> Option<Backend> {
        let Some(health) = self.health() else {
            return self.pick(key, &accept);
        };
        let now = Instant::now();
        let usable = |target: &Backend| health.usable(&target.addr, now) && accept(target);
        self.pick(key, &usable).or_else(|| {
            let up = |target: &Backend| health.up(&target.addr) && accept(target);
            health.passive().then(|| self.pick(key, &up)).flatten()
        })
    }

    /// Counts a request to `target` that failed with `error`, for the passive checks.
    pub(crate) fn failed(&self, target: &Backend, error: &pingora::Error) {
        if let Some(health) = self.health() {
            health.failed(target, error, Instant::now());
        }
    }

    /// Picks a target that `accept` takes: one that the load balancer offers, or else the first
    /// of all the targets. The load balancer offers a few targets only, which may all be
    /// refused when most targets are not usable.
    fn pick(&self, key: &[u8], accept: &dyn Fn(&Backend) -> bool) -> Option<Backend> {
        self.balancer
            .select(key, accept)
            .or_else(|| self.search(key, accept))
    }

    /// Returns the first target that `accept` takes, looking at every target from a place that
    /// `key` decides, or that moves on with every search when there is no key.
    fn search(&self, key: &[u8], accept: &dyn Fn(&Backend) -> bool) -> Option<Backend> {
        let targets = self.resolved.load();
        let start = if key.is_empty() {
            self.turn.fetch_add(1, Ordering::Relaxed)
        } else {
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            hasher.finish() as usize
        };
        let start = start.checked_rem(targets.len())?;
        targets
            .iter()
            .skip(start)
            .chain(targets.iter().take(start))
            .find(|target| accept(target))
            .cloned()
    }

    /// Counts a request in progress at `target` until the guard is dropped, for upstreams that
    /// balance by requests in progress.
    pub(crate) fn track(&self, target: &Backend) -> Option<Inflight> {
        match &self.balancer {
            Balancer::LeastConn(_, counters) => counters.get(&target.addr).map(Inflight::new),
            _ => None,
        }
    }

    /// Resolves the host names again and updates the targets; on failure the targets stay.
    /// New addresses are probed before they get requests.
    async fn refresh(&self) {
        let backends = match resolve(&self.targets).await {
            Ok(backends) => backends,
            Err(problems) => {
                for (index, problem) in problems {
                    tracing::warn!(
                        upstream = %self.name,
                        target = %self.targets[index].address,
                        "{problem}; the last addresses stay in use"
                    );
                }
                return;
            }
        };
        if let Some(watch) = &self.watch {
            let unprobed = watch.update(&backends);
            let health = watch.health();
            health.probe(unprobed, health.reaching()).await;
        }
        self.resolved.store(Arc::new(backends));
        if let Err(error) = self.balancer.update().await {
            tracing::warn!(upstream = %self.name, "cannot update the targets: {error}");
        }
    }
}

/// The host name that a target was resolved from, which TLS sends and checks by default.
#[derive(Clone)]
pub(crate) struct TargetHost(pub(crate) Arc<str>);

/// Resolves the host names of `targets` every 30 seconds while the runtime lives.
async fn keep_resolving(runtime: Weak<UpstreamRuntime>) {
    let start = tokio::time::Instant::now() + RESOLVE_INTERVAL;
    let mut ticks = tokio::time::interval_at(start, RESOLVE_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let Some(runtime) = runtime.upgrade() else {
            return;
        };
        runtime.refresh().await;
    }
}

/// Returns the backends of `targets`: each IP address, and each address of each host name with
/// the weight of the name. The problems come with the index of their target.
pub(crate) async fn resolve(targets: &[Target]) -> Result<BTreeSet<Backend>, Vec<(usize, String)>> {
    let mut backends = BTreeSet::new();
    let mut problems = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let (addresses, host) = match &target.address {
            TargetAddress::Ip(address) => (vec![*address], None),
            TargetAddress::Name { host, port } => match lookup(host, *port).await {
                Ok(addresses) => (addresses, Some(TargetHost(host.as_str().into()))),
                Err(problem) => {
                    problems.push((index, problem));
                    continue;
                }
            },
        };
        for address in addresses {
            match Backend::new_with_weight(&address.to_string(), target.weight as usize) {
                Ok(mut backend) => {
                    if let Some(host) = &host {
                        backend.ext.insert(host.clone());
                    }
                    backends.insert(backend);
                }
                Err(error) => problems.push((index, error.to_string())),
            }
        }
    }
    if problems.is_empty() {
        Ok(backends)
    } else {
        Err(problems)
    }
}

/// Returns the addresses of `host` with `port`, within the time limit.
async fn lookup(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addresses)) => {
            let addresses: Vec<_> = addresses.collect();
            if addresses.is_empty() {
                Err(format!("{host} has no addresses"))
            } else {
                Ok(addresses)
            }
        }
        Ok(Err(error)) => Err(format!("cannot resolve {host}: {error}")),
        Err(_) => Err(format!(
            "cannot resolve {host}: no answer within {}s",
            RESOLVE_TIMEOUT.as_secs()
        )),
    }
}

/// The service discovery of an upstream: the targets as last resolved.
struct Resolved(Arc<ArcSwap<BTreeSet<Backend>>>);

#[async_trait]
impl ServiceDiscovery for Resolved {
    /// Returns the targets as last resolved, all enabled.
    async fn discover(&self) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        Ok((BTreeSet::clone(&self.0.load()), HashMap::new()))
    }
}

/// A load balancer with the selection of one way of balancing.
enum Balancer {
    /// Each request goes to the next target in turn.
    RoundRobin(LoadBalancer<RoundRobin>),
    /// Each request goes to a target picked at random.
    Random(LoadBalancer<Random>),
    /// Each request goes to the target with the fewest requests in progress.
    LeastConn(LoadBalancer<LeastConn>, Arc<Counters>),
    /// Requests with the same key go to the same target.
    ConsistentHash(LoadBalancer<Consistent>),
}

impl Balancer {
    /// Creates the load balancer of `balance` over `backends`.
    fn new(balance: Balance, backends: Backends) -> Self {
        match balance {
            Balance::RoundRobin => Self::RoundRobin(LoadBalancer::from_backends(backends)),
            Balance::Random => Self::Random(LoadBalancer::from_backends(backends)),
            Balance::LeastConn => {
                let counters = Arc::new(Counters::default());
                let balancer =
                    LoadBalancer::from_backends_with_config(backends, Some(counters.clone()));
                Self::LeastConn(balancer, counters)
            }
            Balance::ConsistentHash => Self::ConsistentHash(LoadBalancer::from_backends(backends)),
        }
    }

    /// Reads the targets again and rebuilds the selection if they changed.
    async fn update(&self) -> pingora::Result<()> {
        match self {
            Self::RoundRobin(balancer) => balancer.update().await,
            Self::Random(balancer) => balancer.update().await,
            Self::LeastConn(balancer, _) => balancer.update().await,
            Self::ConsistentHash(balancer) => balancer.update().await,
        }
    }

    /// Picks a healthy target that `accept` takes, for a request with key `key`.
    fn select(&self, key: &[u8], accept: impl Fn(&Backend) -> bool) -> Option<Backend> {
        let accept = |target: &Backend, healthy: bool| healthy && accept(target);
        match self {
            Self::RoundRobin(balancer) => balancer.select_with(key, SELECT_ATTEMPTS, accept),
            Self::Random(balancer) => balancer.select_with(key, SELECT_ATTEMPTS, accept),
            Self::LeastConn(balancer, _) => balancer.select_with(key, SELECT_ATTEMPTS, accept),
            Self::ConsistentHash(balancer) => balancer.select_with(key, SELECT_ATTEMPTS, accept),
        }
    }
}

/// Requests in progress at each target of an upstream, kept while the selection is rebuilt.
#[derive(Default)]
pub(crate) struct Counters(ArcSwap<HashMap<PeerAddr, Arc<AtomicUsize>>>);

impl Counters {
    /// Returns the counter of each of `targets`: the one it had, or a new one, and forgets the
    /// targets that are gone.
    fn assign(&self, targets: &BTreeSet<Backend>) -> Box<[(Backend, Arc<AtomicUsize>)]> {
        let current = self.0.load();
        let mut next = HashMap::with_capacity(targets.len());
        let assigned = targets
            .iter()
            .map(|target| {
                let counter = current.get(&target.addr).cloned().unwrap_or_default();
                next.insert(target.addr.clone(), counter.clone());
                (target.clone(), counter)
            })
            .collect();
        self.0.store(Arc::new(next));
        assigned
    }

    /// Returns the counter of the target at `addr`.
    fn get(&self, addr: &PeerAddr) -> Option<Arc<AtomicUsize>> {
        self.0.load().get(addr).cloned()
    }
}

/// A request in progress at a target, counted until the guard is dropped.
pub(crate) struct Inflight(Arc<AtomicUsize>);

impl Inflight {
    /// Counts one more request on `counter`.
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for Inflight {
    /// The request is over.
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The selection of `least_conn`: the target with the fewest requests in progress relative to
/// its weight, and among equals, each in turn.
pub(crate) struct LeastConn {
    /// The targets with their counters.
    targets: Box<[(Backend, Arc<AtomicUsize>)]>,
    /// Turn of the next request, where the search for the least busy target starts.
    turn: AtomicUsize,
}

impl LeastConn {
    /// Whether target `a` is less busy than target `b`: fewer requests per unit of weight.
    fn less_busy(&self, a: usize, b: usize) -> bool {
        let load = |index: usize| {
            let (target, counter) = &self.targets[index];
            (
                counter.load(Ordering::Relaxed) as u128,
                target.weight as u128,
            )
        };
        let ((a_load, a_weight), (b_load, b_weight)) = (load(a), load(b));
        a_load * b_weight < b_load * a_weight
    }

    /// Returns the indexes of the targets, starting at `start` and wrapping around.
    fn from(&self, start: usize) -> impl Iterator<Item = usize> + use<> {
        let len = self.targets.len();
        (start..len).chain(0..start)
    }
}

impl BackendSelection for LeastConn {
    type Iter = LeastConnIter;
    type Config = Arc<Counters>;

    /// Builds the selection over `backends` with the counters they had.
    fn build_with_config(backends: &BTreeSet<Backend>, counters: &Arc<Counters>) -> Self {
        Self {
            targets: counters.assign(backends),
            turn: AtomicUsize::new(0),
        }
    }

    /// Builds the selection over `backends` with new counters.
    fn build(backends: &BTreeSet<Backend>) -> Self {
        Self::build_with_config(backends, &Arc::default())
    }

    /// Returns the targets from the least busy one, starting the search at the next turn.
    fn iter(self: &Arc<Self>, _key: &[u8]) -> LeastConnIter {
        let start = match self.targets.len() {
            0 => 0,
            len => self.turn.fetch_add(1, Ordering::Relaxed) % len,
        };
        LeastConnIter {
            selection: self.clone(),
            start,
            order: Vec::new(),
            given: 0,
        }
    }
}

/// The targets of [`LeastConn`] from the least busy one.
pub(crate) struct LeastConnIter {
    /// The selection.
    selection: Arc<LeastConn>,
    /// Where the search starts, so that equally busy targets take turns.
    start: usize,
    /// Every target from the least busy one, sorted only when the first one is not taken.
    order: Vec<usize>,
    /// How many targets were given.
    given: usize,
}

impl BackendIter for LeastConnIter {
    /// Gives the least busy target first, in one pass, then the others by how busy they are.
    fn next(&mut self) -> Option<&Backend> {
        let selection = &self.selection;
        let index = if self.given == 0 {
            selection.from(self.start).reduce(|best, index| {
                if selection.less_busy(index, best) {
                    index
                } else {
                    best
                }
            })?
        } else {
            if self.order.is_empty() {
                self.order = selection.from(self.start).collect();
                // A stable sort keeps equally busy targets in turn order.
                self.order.sort_by(|&a, &b| {
                    if selection.less_busy(a, b) {
                        std::cmp::Ordering::Less
                    } else if selection.less_busy(b, a) {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Equal
                    }
                });
            }
            *self.order.get(self.given)?
        };
        self.given += 1;
        Some(&self.selection.targets[index].0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime of an upstream with `targets`, balanced by `balance`.
    async fn runtime(targets: &[&str], balance: Balance) -> Arc<UpstreamRuntime> {
        let settings = Upstream {
            targets: targets
                .iter()
                .map(|target| Target::new(target.parse().unwrap()))
                .collect(),
            balance: Some(balance),
            ..Upstream::default()
        };
        UpstreamRuntime::new(&"app".parse().unwrap(), &settings, None, &plain())
            .await
            .unwrap()
    }

    /// Reaches targets without TLS.
    fn plain() -> Arc<Connect> {
        Arc::new(Connect::new(UpstreamProtocol::H1, None))
    }

    /// The address of `target`.
    fn address(target: &Backend) -> String {
        target.addr.to_string()
    }

    /// With every target equally busy, least_conn takes them in turn; a busy target is avoided
    /// until the others are as busy.
    #[tokio::test]
    async fn picks_the_least_busy_target() {
        let upstream = runtime(&["10.0.0.1:80", "10.0.0.2:80"], Balance::LeastConn).await;
        let picks: Vec<_> = (0..4)
            .map(|_| address(&upstream.select(&[], |_| true).unwrap()))
            .collect();
        assert_eq!(picks.iter().filter(|a| *a == "10.0.0.1:80").count(), 2);

        let first = upstream.select(&[], |_| true).unwrap();
        let busy = upstream.track(&first).unwrap();
        for _ in 0..3 {
            let pick = upstream.select(&[], |_| true).unwrap();
            assert_ne!(address(&pick), address(&first));
        }
        drop(busy);
        let counters = (0..2)
            .map(|_| address(&upstream.select(&[], |_| true).unwrap()))
            .collect::<BTreeSet<_>>();
        assert_eq!(counters.len(), 2);
    }

    /// Weights scale how busy a target may get: weight 2 takes two requests for one.
    #[tokio::test]
    async fn weighs_requests_in_progress() {
        let settings = Upstream {
            targets: vec![
                Target::new("10.0.0.1:80".parse().unwrap()),
                Target {
                    address: "10.0.0.2:80".parse().unwrap(),
                    weight: 2,
                },
            ],
            balance: Some(Balance::LeastConn),
            ..Upstream::default()
        };
        let upstream = UpstreamRuntime::new(&"app".parse().unwrap(), &settings, None, &plain())
            .await
            .unwrap();
        let mut held = Vec::new();
        let mut picks = Vec::new();
        for _ in 0..3 {
            let pick = upstream.select(&[], |_| true).unwrap();
            held.push(upstream.track(&pick).unwrap());
            picks.push(address(&pick));
        }
        picks.sort();
        assert_eq!(picks, ["10.0.0.1:80", "10.0.0.2:80", "10.0.0.2:80"]);
    }

    /// The selection skips what `accept` refuses, and other ways of balancing count nothing.
    #[tokio::test]
    async fn skips_refused_targets() {
        for balance in [
            Balance::RoundRobin,
            Balance::Random,
            Balance::LeastConn,
            Balance::ConsistentHash,
        ] {
            let upstream = runtime(&["10.0.0.1:80", "10.0.0.2:80"], balance).await;
            for _ in 0..4 {
                let pick = upstream
                    .select(b"key", |target| address(target) != "10.0.0.1:80")
                    .unwrap();
                assert_eq!(address(&pick), "10.0.0.2:80", "{balance:?}");
            }
            let none = upstream.select(b"key", |_| false);
            assert!(none.is_none(), "{balance:?}");
            let pick = upstream.select(b"key", |_| true).unwrap();
            assert_eq!(
                upstream.track(&pick).is_some(),
                balance == Balance::LeastConn
            );
        }
    }

    /// When the load balancer offers only refused targets, every target is looked at: the one
    /// usable target among many is always found, and the same one for the same key.
    #[tokio::test]
    async fn finds_the_last_usable_target() {
        let addresses: Vec<String> = (1..=40).map(|i| format!("10.0.0.{i}:80")).collect();
        let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
        for balance in [
            Balance::RoundRobin,
            Balance::Random,
            Balance::LeastConn,
            Balance::ConsistentHash,
        ] {
            let upstream = runtime(&addresses, balance).await;
            for key in 0..50 {
                let key = format!("user-{key}");
                let pick =
                    upstream.select(key.as_bytes(), |target| address(target) == "10.0.0.7:80");
                assert_eq!(
                    pick.map(|pick| address(&pick)).as_deref(),
                    Some("10.0.0.7:80")
                );
            }
            let two = |target: &Backend| {
                matches!(address(target).as_str(), "10.0.0.7:80" | "10.0.0.9:80")
            };
            let first = address(&upstream.select(b"key", two).unwrap());
            let again = address(&upstream.select(b"key", two).unwrap());
            if balance == Balance::ConsistentHash {
                assert_eq!(first, again);
            }
        }
    }

    /// Consistent hashing sends a key to the same target every time.
    #[tokio::test]
    async fn hashes_keys_to_targets() {
        let upstream = runtime(
            &["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"],
            Balance::ConsistentHash,
        )
        .await;
        let mut targets = BTreeSet::new();
        for key in 0..50 {
            let key = format!("user-{key}");
            let first = address(&upstream.select(key.as_bytes(), |_| true).unwrap());
            for _ in 0..3 {
                let again = address(&upstream.select(key.as_bytes(), |_| true).unwrap());
                assert_eq!(again, first);
            }
            targets.insert(first);
        }
        assert_eq!(targets.len(), 3);
    }

    /// Host names are resolved, and a name that does not resolve is reported with its index.
    #[tokio::test]
    async fn resolves_host_names() {
        let targets: Vec<Target> = ["127.0.0.1:81", "localhost:80"]
            .iter()
            .map(|target| Target::new(target.parse().unwrap()))
            .collect();
        let backends = resolve(&targets).await.unwrap();
        let named: Vec<_> = backends
            .iter()
            .filter(|backend| backend.addr.as_inet().is_some_and(|a| a.port() == 80))
            .collect();
        assert!(!named.is_empty());
        for backend in named {
            let host = backend.ext.get::<TargetHost>().map(|host| &*host.0);
            assert_eq!(host, Some("localhost"));
        }
        let unknown = vec![
            Target::new("127.0.0.1:81".parse().unwrap()),
            Target::new("unknown.invalid:80".parse().unwrap()),
        ];
        let problems = resolve(&unknown).await.unwrap_err();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].0, 1);
        assert!(problems[0].1.contains("unknown.invalid"), "{problems:?}");
    }

    /// A refresh takes the addresses that the names have now.
    #[tokio::test]
    async fn refreshes_the_targets() {
        let upstream = runtime(&["10.0.0.1:80"], Balance::RoundRobin).await;
        let pick = upstream.select(&[], |_| true).unwrap();
        assert_eq!(address(&pick), "10.0.0.1:80");
        let moved = Backend::new("10.0.0.9:80").unwrap();
        upstream.resolved.store(Arc::new(BTreeSet::from([moved])));
        upstream.balancer.update().await.unwrap();
        let pick = upstream.select(&[], |_| true).unwrap();
        assert_eq!(address(&pick), "10.0.0.9:80");
    }
}
