//! Traffic of the last minute, by second: how many requests ended, how many failed, and how long
//! they took. Each route, each upstream and all requests together count in a window of their
//! own, which the Admin API reads for the dashboard.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use wormway_runtime::{PeriodReport, SeriesReport, StatsReport, TrafficReport};

use crate::snapshot::GatewaySnapshot;

/// Full seconds that a report covers.
const SECONDS: u64 = 60;
/// Slots of a window: the seconds of a report, the second in progress, and a few to spare for
/// requests that end late. A power of two.
const SLOTS: usize = 64;
/// Durations below `2^FIRST_EXPONENT` microseconds, 128 µs, share the first bucket.
const FIRST_EXPONENT: u32 = 7;
/// Durations from `2^LAST_EXPONENT` microseconds, about 67 seconds, share the last bucket.
const LAST_EXPONENT: u32 = 26;
/// Buckets of the durations: the first, four for each power of two in between, the last.
const BUCKETS: usize = 1 + 4 * (LAST_EXPONENT - FIRST_EXPONENT) as usize + 1;
/// Second of a slot that has counted nothing yet.
const NEVER: u64 = u64::MAX;

/// When the windows started counting seconds.
static START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Returns the second in progress, counted from the first call.
pub(crate) fn second() -> u64 {
    START.elapsed().as_secs()
}

/// The requests of one route, one upstream or of all requests, by second over the last minute.
#[derive(Default)]
pub(crate) struct Window {
    /// One slot per second, taken in turn; allocated by the first request, about 21 KiB.
    slots: OnceLock<Box<[Slot; SLOTS]>>,
}

impl Window {
    /// Counts a request that ended in `second`, as an error if `error`, and with `duration` if
    /// it is known. The first request of a second clears the slot of the second that it
    /// replaces; requests that end at that moment on other threads may be lost.
    pub(crate) fn record(&self, second: u64, error: bool, duration: Option<Duration>) {
        let slots = self
            .slots
            .get_or_init(|| Box::new([const { Slot::new() }; SLOTS]));
        let slot = &slots[slot_index(second)];
        let held = slot.second.load(Ordering::Acquire);
        if held != second {
            // A thread held up for longer than the window would count in a later second.
            if held != NEVER && held > second {
                return;
            }
            if slot
                .second
                .compare_exchange(held, second, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.clear();
            }
        }
        slot.requests.fetch_add(1, Ordering::Relaxed);
        if error {
            slot.errors.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(duration) = duration {
            slot.buckets[bucket(duration)].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the full seconds before second `now`, the oldest first, and their total.
    pub(crate) fn report(&self, now: u64) -> SeriesReport {
        let mut seconds = Vec::new();
        let mut total = Counts::default();
        for back in (1..=SECONDS).rev() {
            let counts = now
                .checked_sub(back)
                .and_then(|second| self.read(second))
                .unwrap_or_default();
            seconds.push(counts.report());
            total.add(&counts);
        }
        SeriesReport {
            seconds,
            total: total.report(),
        }
    }

    /// Returns the counts of `second`, if its slot still holds them.
    fn read(&self, second: u64) -> Option<Counts> {
        let slot = &self.slots.get()?[slot_index(second)];
        if slot.second.load(Ordering::Acquire) != second {
            return None;
        }
        let mut counts = Counts {
            requests: u64::from(slot.requests.load(Ordering::Relaxed)),
            errors: u64::from(slot.errors.load(Ordering::Relaxed)),
            buckets: [0; BUCKETS],
        };
        for (count, bucket) in counts.buckets.iter_mut().zip(&slot.buckets) {
            *count = u64::from(bucket.load(Ordering::Relaxed));
        }
        Some(counts)
    }
}

/// Returns the slot of `second`.
fn slot_index(second: u64) -> usize {
    // The remainder is below SLOTS, so it fits.
    (second % SLOTS as u64) as usize
}

/// The requests of one second.
struct Slot {
    /// The second whose requests the slot counts, or [`NEVER`].
    second: AtomicU64,
    /// Requests that ended.
    requests: AtomicU32,
    /// Those answered with status 500 or above.
    errors: AtomicU32,
    /// Durations, by bucket.
    buckets: [AtomicU32; BUCKETS],
}

impl Slot {
    /// Creates a slot that has counted nothing.
    const fn new() -> Self {
        Self {
            second: AtomicU64::new(NEVER),
            requests: AtomicU32::new(0),
            errors: AtomicU32::new(0),
            buckets: [const { AtomicU32::new(0) }; BUCKETS],
        }
    }

    /// Sets the counts to zero for the next second.
    fn clear(&self) {
        self.requests.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

/// Counts read from one or more slots.
struct Counts {
    /// Requests that ended.
    requests: u64,
    /// Those answered with status 500 or above.
    errors: u64,
    /// Durations, by bucket.
    buckets: [u64; BUCKETS],
}

impl Default for Counts {
    /// Nothing counted.
    fn default() -> Self {
        Self {
            requests: 0,
            errors: 0,
            buckets: [0; BUCKETS],
        }
    }
}

impl Counts {
    /// Adds the counts of `other`.
    fn add(&mut self, other: &Counts) {
        self.requests += other.requests;
        self.errors += other.errors;
        for (count, more) in self.buckets.iter_mut().zip(&other.buckets) {
            *count += more;
        }
    }

    /// Returns the counts with the median and the 99th percentile of the durations.
    fn report(&self) -> PeriodReport {
        PeriodReport {
            requests: self.requests,
            errors: self.errors,
            p50: percentile(&self.buckets, 50),
            p99: percentile(&self.buckets, 99),
        }
    }
}

/// Returns the bucket of `duration`: four for each power of two of microseconds, so that the
/// middle of a bucket is off by at most 12.5% from any duration in it.
fn bucket(duration: Duration) -> usize {
    let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
    if micros < 1 << FIRST_EXPONENT {
        return 0;
    }
    let exponent = u64::BITS - 1 - micros.leading_zeros();
    if exponent >= LAST_EXPONENT {
        return BUCKETS - 1;
    }
    // The two bits after the leading one pick the quarter of the power of two.
    let quarter = (micros >> (exponent - 2)) & 3;
    1 + 4 * (exponent - FIRST_EXPONENT) as usize + quarter as usize
}

/// Returns the duration that bucket `index` stands for: its middle, half of the first bucket,
/// or the start of the last.
fn middle(index: usize) -> Duration {
    if index == 0 {
        return Duration::from_micros(1 << (FIRST_EXPONENT - 1));
    }
    if index >= BUCKETS - 1 {
        return Duration::from_micros(1 << LAST_EXPONENT);
    }
    let offset = index - 1;
    // The bucket covers [quarter * (4 + q), quarter * (5 + q)) microseconds.
    let quarter = 1u64 << (FIRST_EXPONENT as usize + offset / 4 - 2);
    let q = (offset % 4) as u64;
    Duration::from_micros(quarter * (4 + q) + quarter / 2)
}

/// Returns the duration that `percent` percent of the counted durations stay within, `None`
/// when nothing was counted.
fn percentile(buckets: &[u64; BUCKETS], percent: u64) -> Option<Duration> {
    let count: u64 = buckets.iter().sum();
    let rank = (count * percent).div_ceil(100).max(1);
    let mut seen = 0;
    for (index, in_bucket) in buckets.iter().enumerate() {
        seen += in_bucket;
        if seen >= rank {
            return Some(middle(index));
        }
    }
    None
}

/// Reports the traffic of the routes and upstreams of the snapshot in effect.
pub(crate) struct Report(pub(crate) Arc<ArcSwap<GatewaySnapshot>>);

impl StatsReport for Report {
    /// Returns the last full seconds of every window of the snapshot in effect.
    fn traffic(&self) -> TrafficReport {
        let elapsed = START.elapsed();
        let now = elapsed.as_secs();
        let until = SystemTime::now() - Duration::from_nanos(u64::from(elapsed.subsec_nanos()));
        let snapshot = self.0.load();
        TrafficReport {
            until,
            all: snapshot.all.report(now),
            routes: snapshot
                .routes()
                .map(|route| (route.name.clone(), route.stats.report(now)))
                .collect(),
            upstreams: snapshot
                .upstreams()
                .map(|upstream| (upstream.name().clone(), upstream.stats.report(now)))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A duration of `micros` microseconds.
    fn micros(micros: u64) -> Duration {
        Duration::from_micros(micros)
    }

    /// Buckets split each power of two in four, with one bucket below and one above.
    #[test]
    fn puts_durations_in_buckets() {
        assert_eq!(bucket(micros(0)), 0);
        assert_eq!(bucket(micros(127)), 0);
        assert_eq!(bucket(micros(128)), 1);
        assert_eq!(bucket(micros(159)), 1);
        assert_eq!(bucket(micros(160)), 2);
        assert_eq!(bucket(micros(255)), 4);
        assert_eq!(bucket(micros(256)), 5);
        assert_eq!(bucket(micros((1 << 26) - 1)), BUCKETS - 2);
        assert_eq!(bucket(micros(1 << 26)), BUCKETS - 1);
        assert_eq!(bucket(Duration::MAX), BUCKETS - 1);
        for index in 0..BUCKETS {
            assert_eq!(bucket(middle(index)), index, "bucket {index}");
        }
        assert_eq!(middle(1), micros(144));
        assert_eq!(middle(5), micros(288));
    }

    /// Percentiles take the bucket that holds the rank, and nothing without durations.
    #[test]
    fn finds_percentiles() {
        let mut buckets = [0; BUCKETS];
        assert_eq!(percentile(&buckets, 50), None);
        buckets[bucket(micros(1_000))] = 98;
        buckets[bucket(micros(50_000))] = 2;
        assert_eq!(
            percentile(&buckets, 50),
            Some(middle(bucket(micros(1_000))))
        );
        assert_eq!(
            percentile(&buckets, 98),
            Some(middle(bucket(micros(1_000))))
        );
        assert_eq!(
            percentile(&buckets, 99),
            Some(middle(bucket(micros(50_000))))
        );
        let mut single = [0; BUCKETS];
        single[3] = 1;
        assert_eq!(percentile(&single, 50), Some(middle(3)));
        assert_eq!(percentile(&single, 99), Some(middle(3)));
    }

    /// A report covers the 60 full seconds before the one in progress, oldest first, with
    /// their total; requests without a duration count, but not in the percentiles.
    #[test]
    fn reports_the_last_full_seconds() {
        let window = Window::default();
        assert_eq!(window.report(100).seconds.len(), 60);
        assert_eq!(window.report(100).total, PeriodReport::default());
        window.record(39, false, Some(micros(1_000)));
        window.record(40, false, Some(micros(1_000)));
        window.record(40, true, Some(micros(20_000)));
        window.record(99, false, None);
        window.record(100, false, Some(micros(1_000)));

        let report = window.report(100);
        assert_eq!(report.seconds.len(), 60);
        let first = report.seconds[0];
        assert_eq!((first.requests, first.errors), (2, 1));
        assert_eq!(first.p50, Some(middle(bucket(micros(1_000)))));
        assert_eq!(first.p99, Some(middle(bucket(micros(20_000)))));
        let last = report.seconds[59];
        assert_eq!((last.requests, last.errors, last.p50), (1, 0, None));
        assert_eq!(report.total.requests, 3);
        assert_eq!(report.total.errors, 1);
        assert_eq!(report.total.p99, Some(middle(bucket(micros(20_000)))));
        assert_eq!(report.seconds.iter().map(|s| s.requests).sum::<u64>(), 3);
    }

    /// A slot that comes round again starts from zero, and what it held is gone from reports;
    /// requests of a second that a later one has replaced are dropped.
    #[test]
    fn reuses_slots() {
        let window = Window::default();
        window.record(5, true, Some(micros(1_000)));
        window.record(5 + SLOTS as u64, false, None);
        window.record(5, true, None);
        let report = window.report(6 + SLOTS as u64);
        assert_eq!(report.total.requests, 1);
        assert_eq!(report.total.errors, 0);
        assert_eq!(report.seconds[59].requests, 1);
        assert_eq!(window.report(6).total.requests, 0);
    }

    /// Early in the life of the process, seconds before the first count as empty.
    #[test]
    fn reports_seconds_before_the_start_as_empty() {
        let window = Window::default();
        window.record(0, false, Some(micros(500)));
        let report = window.report(1);
        assert_eq!(report.seconds.len(), 60);
        assert_eq!(report.seconds[59].requests, 1);
        assert_eq!(report.total.requests, 1);
    }
}
