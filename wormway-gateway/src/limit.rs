//! Rate limits of routes: a bucket of requests for each key, as the generic cell rate algorithm
//! (GCRA) keeps one, in a bounded cache.
//!
//! A bucket is a single time, the moment it would be full again. A request is allowed while
//! that moment is no further ahead than the bucket holds beyond one request, and moves it one
//! interval further. Each request is counted exactly, and the time to wait comes out of the
//! same arithmetic.

use std::convert::Infallible;
use std::hash::{BuildHasher, Hash, RandomState};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quick_cache::sync::Cache;
use wormway_core::config::{RateLimit, RateLimitKey};

/// Most keys one rate limit keeps. When it is full, keys seen once go before the others.
const MAX_KEYS: usize = 100_000;

/// What a request is counted by.
#[derive(Hash)]
pub(crate) enum Key<'a> {
    /// The IP address of the client.
    Ip(IpAddr),
    /// The value of a request header.
    Value(&'a [u8]),
    /// The route: every request counts in the same bucket.
    Route,
}

/// The rate limit of a route: a bucket for each key.
pub(crate) struct RateLimiter {
    /// The settings, so that a configuration with the same ones keeps the buckets.
    settings: RateLimit,
    /// What requests are counted by.
    key: RateLimitKey,
    /// Nanoseconds in which a bucket gets one request back: `per` divided by `requests`.
    interval: u64,
    /// Nanoseconds that the full moment of a bucket may lie ahead and still allow a request:
    /// `requests - 1` intervals, so that a full bucket allows `requests` at once.
    tolerance: u64,
    /// The time the full moments count from.
    start: Instant,
    /// The full moment of the bucket of each key, in nanoseconds since `start`, by the hash of
    /// the key.
    buckets: Cache<u64, Arc<AtomicU64>>,
    /// Hashes the keys with a seed of its own, so that clients cannot aim at a bucket.
    hasher: RandomState,
}

impl RateLimiter {
    /// Creates the rate limit of `settings`, with every bucket full.
    pub(crate) fn new(settings: &RateLimit) -> Self {
        let per = u64::try_from(settings.per.get().as_nanos()).unwrap_or(u64::MAX);
        let requests = u64::from(settings.requests.max(1));
        let interval = (per / requests).max(1);
        Self {
            settings: settings.clone(),
            key: settings.key(),
            interval,
            tolerance: interval.saturating_mul(requests - 1),
            start: Instant::now(),
            buckets: Cache::new(MAX_KEYS),
            hasher: RandomState::new(),
        }
    }

    /// Whether the rate limit counts as `settings` say, so that a configuration with them can
    /// keep its buckets.
    pub(crate) fn serves(&self, settings: &RateLimit) -> bool {
        self.settings == *settings
    }

    /// Returns what requests are counted by.
    pub(crate) fn key(&self) -> &RateLimitKey {
        &self.key
    }

    /// Counts a request of `key` at `now`, or returns how long the key has to wait for its
    /// next request when its bucket is empty.
    pub(crate) fn check(&self, key: &Key<'_>, now: Instant) -> Result<(), Duration> {
        let hash = self.hasher.hash_one(key);
        let Ok(bucket) = self
            .buckets
            .get_or_insert_with(&hash, || Ok::<_, Infallible>(Arc::default()));
        let now =
            u64::try_from(now.saturating_duration_since(self.start).as_nanos()).unwrap_or(u64::MAX);
        take(&bucket, now, self.interval, self.tolerance).map_err(Duration::from_nanos)
    }
}

/// Takes a request at `now` from the bucket whose full moment is `full`: allowed while that
/// moment lies at most `tolerance` ahead, and then `interval` further ahead. Returns how long
/// to wait otherwise. Times are in nanoseconds; a moment in the past means a full bucket.
fn take(full: &AtomicU64, now: u64, interval: u64, tolerance: u64) -> Result<(), u64> {
    let mut current = full.load(Ordering::Relaxed);
    loop {
        let from = current.max(now);
        let ahead = from - now;
        if ahead > tolerance {
            return Err(ahead - tolerance);
        }
        let next = from.saturating_add(interval);
        match full.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(seen) => current = seen,
        }
    }
}

/// Returns the seconds of a `Retry-After` header for a wait of `wait`: rounded up, at least 1.
pub(crate) fn retry_after(wait: Duration) -> u64 {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    seconds.max(1)
}

#[cfg(test)]
mod tests {
    use wormway_core::config::Duration as ConfigDuration;

    use super::*;

    /// A rate limit of `requests` per `per`, counted by client IP address.
    fn limit(requests: u32, per: &str) -> RateLimit {
        RateLimit {
            requests,
            per: per.parse::<ConfigDuration>().unwrap(),
            key: None,
        }
    }

    /// A full bucket of 3 allows 3 requests at once, then one per interval; the wait is what
    /// is left of the interval.
    #[test]
    fn allows_a_burst_then_one_per_interval() {
        let full = AtomicU64::new(0);
        let (interval, tolerance) = (100, 200);
        for _ in 0..3 {
            assert_eq!(take(&full, 1_000, interval, tolerance), Ok(()));
        }
        assert_eq!(take(&full, 1_000, interval, tolerance), Err(100));
        assert_eq!(take(&full, 1_040, interval, tolerance), Err(60));
        assert_eq!(take(&full, 1_100, interval, tolerance), Ok(()));
        assert_eq!(take(&full, 1_100, interval, tolerance), Err(100));
        // After three intervals without requests, the bucket is full again.
        assert_eq!(full.load(Ordering::Relaxed), 1_400);
        for _ in 0..3 {
            assert_eq!(take(&full, 1_400, interval, tolerance), Ok(()));
        }
        assert_eq!(take(&full, 1_400, interval, tolerance), Err(100));
    }

    /// Requests counted at once on several threads add up exactly.
    #[test]
    fn counts_concurrent_requests_exactly() {
        let full = Arc::new(AtomicU64::new(0));
        let allowed: usize = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let full = full.clone();
                    scope.spawn(move || {
                        (0..1_000)
                            .filter(|_| take(&full, 5, 1, 4_999).is_ok())
                            .count()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .sum()
        });
        assert_eq!(allowed, 5_000);
    }

    /// Each key has a bucket of its own, holding `requests`; the wait is what is left of an
    /// interval of `per` divided by `requests`.
    #[test]
    fn keeps_a_bucket_for_each_key() {
        let limiter = RateLimiter::new(&limit(2, "1m"));
        let now = Instant::now();
        let a = Key::Value(b"a");
        assert_eq!(limiter.check(&a, now), Ok(()));
        assert_eq!(limiter.check(&a, now), Ok(()));
        assert_eq!(limiter.check(&a, now), Err(Duration::from_secs(30)));
        let later = now + Duration::from_secs(10);
        assert_eq!(limiter.check(&a, later), Err(Duration::from_secs(20)));
        let ip = Key::Ip(IpAddr::from([127, 0, 0, 1]));
        assert_eq!(limiter.check(&ip, later), Ok(()));
        assert_eq!(limiter.check(&Key::Value(b"b"), later), Ok(()));
        assert_eq!(limiter.check(&a, now + Duration::from_secs(30)), Ok(()));
        assert!(limiter.serves(&limit(2, "1m")));
        assert!(!limiter.serves(&limit(2, "1s")));
    }

    /// More requests per period than nanoseconds still allow one request per nanosecond.
    #[test]
    fn takes_at_least_a_nanosecond_per_request() {
        let limiter = RateLimiter::new(&limit(u32::MAX, "1ms"));
        assert_eq!(limiter.interval, 1);
        assert_eq!(limiter.tolerance, u64::from(u32::MAX) - 1);
    }

    /// Waits round up to whole seconds, and are never shorter than one second.
    #[test]
    fn rounds_retry_after_up() {
        assert_eq!(retry_after(Duration::ZERO), 1);
        assert_eq!(retry_after(Duration::from_millis(1)), 1);
        assert_eq!(retry_after(Duration::from_secs(30)), 30);
        assert_eq!(retry_after(Duration::from_millis(29_001)), 30);
    }
}
