//! Health of the targets of an upstream: the results of the active health checks, which probe
//! every target at an interval, and of the passive ones, which count failed requests.
//!
//! The health of an upstream outlives its runtimes, the load balancers of successive
//! configurations, as long as the health checks stay the same: a new runtime takes over the
//! health of the one before, so the targets that stay keep their health when the others
//! change. Every runtime registers the targets it balances over through a [`Watch`]; the health
//! follows every address registered by a live runtime, keyed by the address alone, and forgets
//! the others.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use pingora::lb::Backend;
use pingora::protocols::l4::socket::SocketAddr as PeerAddr;
use tokio::task::JoinSet;
use tracing::{info, warn};
use wormway_core::config::{HealthCheck, HealthCheckKind, Name, PassiveCheck, Upstream};
use wormway_runtime::TargetState;

use crate::probe::{self, Prober};
use crate::upstream::{Connect, TargetHost};

/// Health of the targets of one upstream, shared by its runtimes while its checks stay the
/// same.
pub(crate) struct UpstreamHealth {
    /// The upstream, for the log.
    name: Name,
    /// Active checks, if any.
    check: Option<HealthCheck>,
    /// Passive checks, if any.
    passive: Option<PassiveCheck>,
    /// Makes the probes.
    prober: Arc<Prober>,
    /// How the probes reach the targets: as in the snapshot in effect, or as in the one that
    /// created the health.
    connect: ArcSwap<Connect>,
    /// Health of every address that a live runtime balances over.
    targets: ArcSwap<HashMap<PeerAddr, Arc<TargetHealth>>>,
    /// The targets of each live runtime, by registration.
    watched: Mutex<HashMap<u64, BTreeSet<Backend>>>,
    /// The next registration.
    next_watch: AtomicU64,
    /// Start of the clock that the passive checks count on.
    epoch: Instant,
}

impl UpstreamHealth {
    /// Creates the health of upstream `name` with the checks of `settings`, or `None` without
    /// checks. The probes reach the targets through `connect` until a snapshot hands over
    /// another, and start after one interval; they stop when the health is dropped.
    pub(crate) fn new(
        name: &Name,
        settings: &Upstream,
        prober: Arc<Prober>,
        connect: Arc<Connect>,
    ) -> Option<Arc<Self>> {
        if settings.health_check.is_none() && settings.passive.is_none() {
            return None;
        }
        let health = Arc::new(Self {
            name: name.clone(),
            check: settings.health_check.clone(),
            passive: settings.passive.clone(),
            prober,
            connect: ArcSwap::new(connect),
            targets: ArcSwap::default(),
            watched: Mutex::default(),
            next_watch: AtomicU64::new(0),
            epoch: Instant::now(),
        });
        if let Some(check) = &health.check {
            tokio::spawn(keep_checking(
                Arc::downgrade(&health),
                check.interval().get(),
            ));
        }
        Some(health)
    }

    /// Whether the health checks are those of `settings`.
    pub(crate) fn checks_as(&self, settings: &Upstream) -> bool {
        self.check == settings.health_check && self.passive == settings.passive
    }

    /// Whether the passive checks are on.
    pub(crate) fn passive(&self) -> bool {
        self.passive.is_some()
    }

    /// Returns how the active checks probe the targets, if they are on.
    pub(crate) fn kind(&self) -> Option<HealthCheckKind> {
        self.check.as_ref().map(|check| check.kind)
    }

    /// Returns whether the target at `addr` gets requests at `now`, since when, and why not.
    pub(crate) fn report(
        &self,
        addr: &PeerAddr,
        now: Instant,
    ) -> (TargetState, Option<SystemTime>, Option<String>) {
        let Some(target) = self.target(addr) else {
            return (TargetState::Healthy, None, None);
        };
        let record = target.lock();
        if record.healthy == Some(false) {
            return (TargetState::Unhealthy, record.since, record.reason.clone());
        }
        if target.out_until.load(Ordering::Relaxed) > self.clock(now)
            && let Some(out) = &record.out
        {
            let state = TargetState::Ejected { until: out.until };
            return (state, Some(out.since), Some(out.reason.clone()));
        }
        (TargetState::Healthy, record.since, None)
    }

    /// Makes the probes reach the targets through `connect` from now on.
    pub(crate) fn reach(&self, connect: Arc<Connect>) {
        self.connect.store(connect);
    }

    /// Returns how the probes reach the targets.
    pub(crate) fn reaching(&self) -> Arc<Connect> {
        self.connect.load_full()
    }

    /// Registers a runtime, which has no targets until [`Watch::update`].
    pub(crate) fn watch(self: &Arc<Self>) -> Watch {
        Watch {
            health: self.clone(),
            id: self.next_watch.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Whether the target at `addr` may get requests at `now`: the active checks pass and the
    /// passive checks have not taken it out. Targets that the health does not follow may.
    pub(crate) fn usable(&self, addr: &PeerAddr, now: Instant) -> bool {
        self.targets.load().get(addr).is_none_or(|target| {
            target.up.load(Ordering::Relaxed)
                && target.out_until.load(Ordering::Relaxed) <= self.clock(now)
        })
    }

    /// Whether the active checks let the target at `addr` get requests.
    pub(crate) fn up(&self, addr: &PeerAddr) -> bool {
        self.targets
            .load()
            .get(addr)
            .is_none_or(|target| target.up.load(Ordering::Relaxed))
    }

    /// Probes `targets` at once through `connect`, and takes the results.
    pub(crate) async fn probe(self: &Arc<Self>, targets: Vec<Backend>, connect: Arc<Connect>) {
        if self.check.is_none() || targets.is_empty() {
            return;
        }
        let mut probes = JoinSet::new();
        for target in targets {
            let (health, connect) = (self.clone(), connect.clone());
            probes.spawn(async move {
                let Some(check) = &health.check else {
                    return (target, Ok(()));
                };
                let result = health.prober.probe(check, &connect, &target).await;
                (target, result)
            });
        }
        while let Some(done) = probes.join_next().await {
            match done {
                Ok((target, result)) => self.observe(&target, result),
                Err(error) => warn!(upstream = %self.name, "a health check stopped: {error}"),
            }
        }
    }

    /// Takes the result of a probe of `target`: the first result decides, then `healthy` or
    /// `unhealthy` results in a row change the health.
    fn observe(&self, target: &Backend, result: Result<(), String>) {
        let (Some(check), Some(health)) = (&self.check, self.target(&target.addr)) else {
            return;
        };
        let passed = result.is_ok();
        let mut record = health.lock();
        let before = record.healthy;
        if let Err(reason) = result {
            record.reason = Some(reason);
        }
        if !record.observe(passed, check.healthy(), check.unhealthy()) {
            return;
        }
        record.since = Some(SystemTime::now());
        health.up.store(passed, Ordering::Relaxed);
        let reason = record.reason.clone().unwrap_or_default();
        drop(record);
        let host = target
            .ext
            .get::<TargetHost>()
            .map(|TargetHost(host)| &**host);
        if !passed {
            warn!(upstream = %self.name, target = %target.addr, host, "target is unhealthy: {reason}");
        } else if before == Some(false) {
            info!(upstream = %self.name, target = %target.addr, host, "target is healthy again");
        }
    }

    /// Counts a request to `target` that failed with `error` at `now`. When the passive checks
    /// count enough failures, the target gets no requests for a while.
    pub(crate) fn failed(&self, target: &Backend, error: &pingora::Error, now: Instant) {
        let (Some(passive), Some(health)) = (&self.passive, self.target(&target.addr)) else {
            return;
        };
        let clock = self.clock(now);
        if health.out_until.load(Ordering::Relaxed) > clock {
            return;
        }
        let window = passive.fail_timeout().get();
        let mut record = health.lock();
        if record.count_failure(now, window) < passive.max_fails() {
            return;
        }
        record.fails = 0;
        let reason = probe::describe(error);
        let since = SystemTime::now();
        record.out = Some(Ejection {
            since,
            until: since + window,
            reason: reason.clone(),
        });
        health
            .out_until
            .store(clock + millis(window), Ordering::Relaxed);
        drop(record);
        let host = target
            .ext
            .get::<TargetHost>()
            .map(|TargetHost(host)| &**host);
        warn!(
            upstream = %self.name,
            target = %target.addr,
            host,
            "requests to the target failed {} within {}, so it gets none for {}: {reason}",
            times(passive.max_fails()),
            passive.fail_timeout(),
            passive.fail_timeout(),
        );
    }

    /// Returns the health of the target at `addr`, if the health follows it.
    fn target(&self, addr: &PeerAddr) -> Option<Arc<TargetHealth>> {
        self.targets.load().get(addr).cloned()
    }

    /// Returns `now` on the clock of the passive checks, in milliseconds.
    fn clock(&self, now: Instant) -> u64 {
        millis(now.saturating_duration_since(self.epoch))
    }

    /// Sets the targets of registration `id`, or withdraws them if `None`, and returns those of
    /// its targets that were never probed.
    fn update(&self, id: u64, targets: Option<&BTreeSet<Backend>>) -> Vec<Backend> {
        let mut watched = self.watched.lock().unwrap_or_else(PoisonError::into_inner);
        match targets {
            Some(targets) => watched.insert(id, targets.clone()),
            None => watched.remove(&id),
        };
        let current = self.targets.load();
        let mut next = HashMap::new();
        for target in watched.values().flatten() {
            next.entry(target.addr.clone()).or_insert_with(|| {
                current
                    .get(&target.addr)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(TargetHealth::new(self.check.is_some())))
            });
        }
        let unprobed = targets
            .into_iter()
            .flatten()
            .filter(|target| {
                next.get(&target.addr)
                    .is_some_and(|health| health.unprobed())
            })
            .cloned()
            .collect();
        self.targets.store(Arc::new(next));
        unprobed
    }

    /// Returns every target of the live runtimes, each address once.
    fn watched(&self) -> Vec<Backend> {
        let watched = self.watched.lock().unwrap_or_else(PoisonError::into_inner);
        let mut seen = HashMap::new();
        for target in watched.values().flatten() {
            seen.entry(target.addr.clone())
                .or_insert_with(|| target.clone());
        }
        seen.into_values().collect()
    }
}

/// The targets that one runtime registered with the health of its upstream. Dropping it
/// withdraws them.
pub(crate) struct Watch {
    /// The health.
    health: Arc<UpstreamHealth>,
    /// The registration.
    id: u64,
}

impl Watch {
    /// Returns the health.
    pub(crate) fn health(&self) -> &Arc<UpstreamHealth> {
        &self.health
    }

    /// Sets the targets of the runtime to `targets`, and returns those that were never probed:
    /// they must be before they get requests.
    pub(crate) fn update(&self, targets: &BTreeSet<Backend>) -> Vec<Backend> {
        self.health.update(self.id, Some(targets))
    }
}

impl Drop for Watch {
    /// Withdraws the targets of the runtime.
    fn drop(&mut self) {
        self.health.update(self.id, None);
    }
}

/// Health of one target.
struct TargetHealth {
    /// Whether the active checks let the target get requests; true until probes fail.
    up: AtomicBool,
    /// When the passive checks let the target get requests again, on the clock of the upstream;
    /// 0 when they never took it out.
    out_until: AtomicU64,
    /// The rest, for the checks.
    state: Mutex<TargetRecord>,
}

impl TargetHealth {
    /// A target that was never probed, which the active checks have to probe if `checked`.
    fn new(checked: bool) -> Self {
        Self {
            up: AtomicBool::new(true),
            out_until: AtomicU64::new(0),
            state: Mutex::new(TargetRecord {
                unprobed: checked,
                ..TargetRecord::default()
            }),
        }
    }

    /// Locks the state.
    fn lock(&self) -> MutexGuard<'_, TargetRecord> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the active checks have yet to probe the target.
    fn unprobed(&self) -> bool {
        self.lock().unprobed
    }
}

/// What the checks know about a target besides whether it may get requests.
#[derive(Default)]
struct TargetRecord {
    /// Whether the active checks have yet to probe the target.
    unprobed: bool,
    /// Result of the active checks; `None` before the first probe.
    healthy: Option<bool>,
    /// Probes in a row whose result differs from `healthy`.
    streak: u32,
    /// When the result of the active checks last changed.
    since: Option<SystemTime>,
    /// Why the last probe that failed did.
    reason: Option<String>,
    /// Failed requests counted by the passive checks since `window`.
    fails: u32,
    /// When the passive checks started counting.
    window: Option<Instant>,
    /// The last time the passive checks took the target out.
    out: Option<Ejection>,
}

/// A time the passive checks took a target out.
struct Ejection {
    /// When they took it out.
    since: SystemTime,
    /// When it gets requests again.
    until: SystemTime,
    /// The failure that took it out.
    reason: String,
}

impl TargetRecord {
    /// Takes the result of a probe and returns whether the health changed: the first result
    /// decides, then `rise` passed or `fall` failed probes in a row are needed.
    fn observe(&mut self, passed: bool, rise: u32, fall: u32) -> bool {
        self.unprobed = false;
        let changed = match self.healthy {
            None => true,
            Some(healthy) if healthy == passed => {
                self.streak = 0;
                false
            }
            Some(_) => {
                self.streak += 1;
                self.streak >= if passed { rise } else { fall }
            }
        };
        if changed {
            self.healthy = Some(passed);
            self.streak = 0;
        }
        changed
    }

    /// Counts a failure at `now` and returns the failures within `window` from the first one.
    fn count_failure(&mut self, now: Instant, window: Duration) -> u32 {
        if self
            .window
            .is_none_or(|start| now.saturating_duration_since(start) > window)
        {
            self.window = Some(now);
            self.fails = 0;
        }
        self.fails += 1;
        self.fails
    }
}

/// Probes the targets of `health` every `interval` while it lives.
async fn keep_checking(health: Weak<UpstreamHealth>, interval: Duration) {
    let start = tokio::time::Instant::now() + interval;
    let mut ticks = tokio::time::interval_at(start, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let Some(health) = health.upgrade() else {
            return;
        };
        let targets = health.watched();
        let connect = health.reaching();
        health.probe(targets, connect).await;
    }
}

/// Returns how many times something happened, in words.
fn times(count: u32) -> String {
    match count {
        1 => "once".to_owned(),
        2 => "twice".to_owned(),
        count => format!("{count} times"),
    }
}

/// Returns `duration` in whole milliseconds.
fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use wormway_core::config::{HealthCheckKind, Target, UpstreamProtocol};

    use super::*;

    /// The settings of an upstream with one target and the checks given.
    fn settings(check: Option<HealthCheck>, passive: Option<PassiveCheck>) -> Upstream {
        Upstream {
            targets: vec![Target::new("10.0.0.1:80".parse().unwrap())],
            health_check: check,
            passive,
            ..Upstream::default()
        }
    }

    /// The health of an upstream with `settings`, reached without TLS.
    fn health(settings: &Upstream) -> Arc<UpstreamHealth> {
        let connect = Arc::new(Connect::new(UpstreamProtocol::H1, None));
        let prober = Arc::new(Prober::default());
        UpstreamHealth::new(&"app".parse().unwrap(), settings, prober, connect).unwrap()
    }

    /// The targets at `addresses`.
    fn targets(addresses: &[&str]) -> BTreeSet<Backend> {
        addresses
            .iter()
            .map(|address| Backend::new(address).unwrap())
            .collect()
    }

    /// The address of a target.
    fn addr(address: &str) -> PeerAddr {
        Backend::new(address).unwrap().addr
    }

    /// The first result decides, then it takes `rise` or `fall` results in a row to change;
    /// a result that agrees breaks a streak.
    #[test]
    fn needs_results_in_a_row() {
        let mut state = TargetRecord::default();
        assert!(state.observe(false, 2, 3));
        assert_eq!(state.healthy, Some(false));
        assert!(!state.observe(true, 2, 3));
        assert!(!state.observe(false, 2, 3));
        assert!(!state.observe(true, 2, 3));
        assert!(state.observe(true, 2, 3));
        assert_eq!(state.healthy, Some(true));
        for _ in 0..2 {
            assert!(!state.observe(false, 2, 3));
        }
        assert!(state.observe(false, 2, 3));
        assert_eq!(state.healthy, Some(false));

        let mut fresh = TargetRecord::default();
        assert!(fresh.observe(true, 2, 3));
        assert_eq!(fresh.healthy, Some(true));
    }

    /// Failures count within a window from the first one; a later failure starts a new window.
    #[test]
    fn counts_failures_within_a_window() {
        let mut state = TargetRecord::default();
        let start = Instant::now();
        let window = Duration::from_secs(10);
        assert_eq!(state.count_failure(start, window), 1);
        assert_eq!(
            state.count_failure(start + Duration::from_secs(5), window),
            2
        );
        assert_eq!(
            state.count_failure(start + Duration::from_secs(10), window),
            3
        );
        assert_eq!(
            state.count_failure(start + Duration::from_secs(11), window),
            1
        );
    }

    /// Enough failures take a target out for the fail timeout, and only that target.
    #[tokio::test]
    async fn takes_failing_targets_out_for_a_while() {
        let passive = PassiveCheck {
            max_fails: Some(2),
            fail_timeout: Some(wormway_core::config::Duration::from_secs(10)),
        };
        let health = health(&settings(None, Some(passive)));
        let watch = health.watch();
        let both = targets(&["10.0.0.1:80", "10.0.0.2:80"]);
        assert!(watch.update(&both).is_empty());
        let (first, second) = (both.first().unwrap(), both.last().unwrap());
        let error = pingora::Error::new(pingora::ErrorType::ConnectRefused);
        let now = Instant::now();
        health.failed(first, &error, now);
        assert!(health.usable(&first.addr, now));
        health.failed(first, &error, now + Duration::from_secs(1));
        assert!(!health.usable(&first.addr, now + Duration::from_secs(1)));
        assert!(!health.usable(&first.addr, now + Duration::from_secs(10)));
        assert!(health.usable(&first.addr, now + Duration::from_secs(12)));
        assert!(health.usable(&second.addr, now + Duration::from_secs(1)));
        assert!(health.up(&first.addr));
    }

    /// The report says whether each target gets requests, since when and why not: the active
    /// checks first, then the passive ones; addresses the health does not follow are healthy.
    #[tokio::test]
    async fn reports_why_targets_get_no_requests() {
        let check = HealthCheck {
            kind: HealthCheckKind::Tcp,
            path: None,
            host: None,
            status: None,
            interval: None,
            timeout: None,
            healthy: None,
            unhealthy: None,
        };
        let passive = PassiveCheck {
            max_fails: Some(1),
            fail_timeout: Some(wormway_core::config::Duration::from_secs(10)),
        };
        let health = health(&settings(Some(check), Some(passive)));
        let watch = health.watch();
        let all = targets(&["10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"]);
        assert_eq!(watch.update(&all).len(), 3);
        let [down, out, fine]: [&Backend; 3] = all.iter().collect::<Vec<_>>().try_into().unwrap();
        health.observe(down, Err("status 503".to_owned()));
        health.observe(out, Ok(()));
        health.observe(fine, Ok(()));
        let error = pingora::Error::new(pingora::ErrorType::ConnectRefused);
        health.failed(out, &error, Instant::now());
        health.failed(down, &error, Instant::now());

        let now = Instant::now();
        let (state, since, reason) = health.report(&down.addr, now);
        assert_eq!(state, TargetState::Unhealthy);
        assert!(since.is_some());
        assert_eq!(reason.as_deref(), Some("status 503"));
        let (state, since, reason) = health.report(&out.addr, now);
        let TargetState::Ejected { until } = state else {
            panic!("{state:?}");
        };
        let since = since.expect("ejected at");
        assert_eq!(
            until.duration_since(since).ok(),
            Some(Duration::from_secs(10))
        );
        assert_eq!(reason.as_deref(), Some("connection refused"));
        let (state, since, reason) = health.report(&fine.addr, now);
        assert_eq!(
            (state, since.is_some(), reason),
            (TargetState::Healthy, true, None)
        );
        let unknown = health.report(&addr("10.0.0.9:80"), now);
        assert_eq!(unknown, (TargetState::Healthy, None, None));
    }

    /// Runtimes share the health of the addresses they have in common, and the health forgets
    /// an address when no live runtime has it. Only targets never probed come back from an
    /// update.
    #[tokio::test]
    async fn shares_targets_between_runtimes() {
        let check = HealthCheck {
            kind: HealthCheckKind::Tcp,
            path: None,
            host: None,
            status: None,
            interval: None,
            timeout: None,
            healthy: None,
            unhealthy: None,
        };
        let health = health(&settings(Some(check), None));
        let (old, new) = (health.watch(), health.watch());
        let unprobed = old.update(&targets(&["10.0.0.1:80", "10.0.0.2:80"]));
        assert_eq!(unprobed.len(), 2);
        let down = Backend::new("10.0.0.2:80").unwrap();
        health.observe(&down, Err("connection refused".to_owned()));
        assert!(!health.up(&addr("10.0.0.2:80")));

        let unprobed = new.update(&targets(&["10.0.0.2:80", "10.0.0.3:80"]));
        let unprobed: Vec<String> = unprobed.iter().map(|t| t.addr.to_string()).collect();
        assert_eq!(unprobed, ["10.0.0.3:80"]);
        assert!(!health.up(&addr("10.0.0.2:80")));
        assert!(health.target(&addr("10.0.0.1:80")).is_some());

        drop(old);
        assert!(health.target(&addr("10.0.0.1:80")).is_none());
        assert!(!health.up(&addr("10.0.0.2:80")));
        drop(new);
        assert!(health.target(&addr("10.0.0.2:80")).is_none());
        assert!(health.up(&addr("10.0.0.2:80")));
    }
}
