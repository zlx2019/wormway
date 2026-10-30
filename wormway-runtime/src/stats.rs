//! Traffic of the last minute: the gateway reports it, and the Admin API shows it.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use wormway_core::config::Name;

/// Reports the traffic of the last minute.
pub trait StatsReport: Send + Sync + 'static {
    /// Returns the requests of the last full seconds.
    fn traffic(&self) -> TrafficReport;
}

/// The requests of the last full seconds: all of them, by route and by upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficReport {
    /// When the last of the seconds ended.
    pub until: SystemTime,
    /// Every request.
    pub all: SeriesReport,
    /// The requests of each route in effect.
    pub routes: BTreeMap<Name, SeriesReport>,
    /// The requests of the routes to each upstream in effect. Their durations are those of the
    /// upstream: from picking the first target to the response header of the last one.
    pub upstreams: BTreeMap<Name, SeriesReport>,
}

/// Requests by second, and over all the seconds together.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeriesReport {
    /// Each second, the oldest first.
    pub seconds: Vec<PeriodReport>,
    /// All the seconds together.
    pub total: PeriodReport,
}

/// The requests that ended in a period of time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeriodReport {
    /// Requests that ended.
    pub requests: u64,
    /// Those answered with status 500 or above, the answers of Wormway itself included.
    pub errors: u64,
    /// The median duration; `None` without any duration.
    pub p50: Option<Duration>,
    /// The duration that 99% of the requests stayed within; `None` without any duration.
    pub p99: Option<Duration>,
}
