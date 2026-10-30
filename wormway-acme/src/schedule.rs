//! When to renew certificates, and how long to wait after failures.

use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wormway_tls::IssuedCertificate;

/// Longest wait after failures in a row.
const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

/// Returns when `certificate` should be renewed: when a third of its lifetime is left, 30 days
/// before the end for the 90 days of Let's Encrypt.
pub(crate) fn renewal_time(certificate: &IssuedCertificate) -> SystemTime {
    let info = certificate.info();
    let (start, end) = (time(info.not_before), time(info.not_after));
    let lifetime = end.duration_since(start).unwrap_or_default();
    end.checked_sub(lifetime / 3).unwrap_or(start)
}

/// Returns how long to wait after `failures` failures in a row: an hour, doubling with each
/// further failure up to a day.
pub(crate) fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(5);
    (Duration::from_secs(3600) * (1 << doublings)).min(MAX_BACKOFF)
}

/// Returns a point in the window from `start` to `end`, picked by `random`, as renewal
/// information asks (RFC 9773, section 4.2); `start` when the window is empty.
pub(crate) fn within(start: SystemTime, end: SystemTime, random: u64) -> SystemTime {
    let Ok(width) = end.duration_since(start) else {
        return start;
    };
    let millis = u64::try_from(width.as_millis()).unwrap_or(u64::MAX);
    match random.checked_rem(millis) {
        Some(offset) => start + Duration::from_millis(offset),
        None => start,
    }
}

/// Returns a number that differs from call to call, enough to spread renewals over time.
pub(crate) fn random() -> u64 {
    RandomState::new().hash_one(SystemTime::now())
}

/// Returns the time `seconds` seconds after 1970; times before count as 1970.
fn time(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use wormway_tls::Certificates;

    use super::*;

    /// Hours, for short durations.
    fn hours(hours: u64) -> Duration {
        Duration::from_secs(hours * 3600)
    }

    /// A certificate of 90 days is renewed 30 days before it ends.
    #[test]
    fn renews_when_a_third_is_left() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["site.test".to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 4, 1);
        let cert = params.self_signed(&key).unwrap();
        let issued = Certificates::new(".")
            .read_issued(&cert.pem(), &key.serialize_pem())
            .unwrap();
        let end = time(issued.info().not_after);
        assert_eq!(
            end.duration_since(renewal_time(&issued)).unwrap(),
            hours(30 * 24)
        );
    }

    /// Waits double from an hour after each failure and stop growing at a day.
    #[test]
    fn backs_off_up_to_a_day() {
        let waits: Vec<Duration> = (1..=8).map(backoff).collect();
        let expected = [1, 2, 4, 8, 16, 24, 24, 24].map(hours);
        assert_eq!(waits, expected);
        assert_eq!(backoff(0), hours(1));
        assert_eq!(backoff(u32::MAX), hours(24));
    }

    /// Points stay in the window; an empty or reversed window gives its start.
    #[test]
    fn picks_a_point_in_the_window() {
        let start = UNIX_EPOCH + hours(100);
        let end = start + hours(10);
        for random in [0, 1, 35_999_999, 36_000_000, u64::MAX] {
            let point = within(start, end, random);
            assert!(start <= point && point < end, "{random}");
        }
        assert_eq!(within(start, start, 7), start);
        assert_eq!(within(end, start, 7), end);
        assert_ne!(random(), random());
    }
}
