//! Timestamps as the Admin API and the access log write them, in UTC.

use std::time::{SystemTime, UNIX_EPOCH};

/// Month names of the common log format.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Writes `time` as an RFC 3339 timestamp to the millisecond, as the database writes them, such
/// as `2026-10-29T08:30:00.000Z`. Times before 1970 are written as 1970.
pub fn rfc3339(time: SystemTime) -> String {
    let at = Parts::of(time);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year, at.month, at.day, at.hour, at.minute, at.second, at.millis
    )
}

/// Writes `time` as the common log format of Nginx and Apache does, such as
/// `29/Oct/2026:08:30:00 +0000`. Times before 1970 are written as 1970.
pub fn common_log(time: SystemTime) -> String {
    let at = Parts::of(time);
    let month = MONTHS[(at.month - 1) as usize];
    format!(
        "{:02}/{month}/{:04}:{:02}:{:02}:{:02} +0000",
        at.day, at.year, at.hour, at.minute, at.second
    )
}

/// The date and the time of day of a time, in UTC.
struct Parts {
    /// The year.
    year: u64,
    /// The month, from 1.
    month: u64,
    /// The day of the month, from 1.
    day: u64,
    /// The hour.
    hour: u64,
    /// The minute.
    minute: u64,
    /// The second.
    second: u64,
    /// The millisecond.
    millis: u32,
}

impl Parts {
    /// Splits `time` into its parts.
    fn of(time: SystemTime) -> Self {
        let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = since_epoch.as_secs();
        let (days, rest) = (secs / 86_400, secs % 86_400);
        // The date `days` days after 1970-01-01, after Howard Hinnant's `civil_from_days`: eras
        // of 400 years, with years that start on March 1 so that leap days come last.
        let shifted = days + 719_468;
        let era = shifted / 146_097;
        let day_of_era = shifted % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let month = if month_from_march < 10 {
            month_from_march + 3
        } else {
            month_from_march - 9
        };
        Self {
            year: year_of_era + era * 400 + u64::from(month <= 2),
            month,
            day: day_of_year - (153 * month_from_march + 2) / 5 + 1,
            hour: rest / 3_600,
            minute: rest % 3_600 / 60,
            second: rest % 60,
            millis: since_epoch.subsec_millis(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The time `millis` milliseconds after 1970.
    fn at(millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(millis)
    }

    /// Timestamps match those of Python's datetime, leap days and milliseconds included.
    #[test]
    fn writes_rfc3339_timestamps() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(at(951_782_400_000)), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(1_700_000_000_123)), "2023-11-14T22:13:20.123Z");
        assert_eq!(rfc3339(at(1_761_696_000_000)), "2025-10-29T00:00:00.000Z");
        assert_eq!(rfc3339(at(4_102_444_799_999)), "2099-12-31T23:59:59.999Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
            "1970-01-01T00:00:00.000Z"
        );
    }

    /// The common log format writes the day first, the month by name and the zone.
    #[test]
    fn writes_common_log_timestamps() {
        assert_eq!(common_log(UNIX_EPOCH), "01/Jan/1970:00:00:00 +0000");
        assert_eq!(
            common_log(at(951_782_400_000)),
            "29/Feb/2000:00:00:00 +0000"
        );
        assert_eq!(
            common_log(at(1_700_000_000_123)),
            "14/Nov/2023:22:13:20 +0000"
        );
        assert_eq!(
            common_log(at(4_102_444_799_999)),
            "31/Dec/2099:23:59:59 +0000"
        );
    }
}
