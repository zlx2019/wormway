//! Timestamps as the Admin API writes them, in UTC, and as the logs write them, in the format
//! and the time zone of `[log]`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, SecondsFormat, Utc};

use crate::config::{LogSettings, TimeFormat, TimeZone};

/// Layout of the times of the common log format of Nginx and Apache, such as
/// `29/Oct/2026:08:30:00 +0000`.
const COMMON_LOG: &str = "%d/%b/%Y:%H:%M:%S %z";

/// Writes `time` as an RFC 3339 timestamp to the millisecond, as the database writes them, such
/// as `2026-10-29T08:30:00.000Z`. Times before 1970 are written as 1970.
pub fn rfc3339(time: SystemTime) -> String {
    let at = Parts::of(time);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        at.year, at.month, at.day, at.hour, at.minute, at.second, at.millis
    )
}

/// Digits of the second in the RFC 3339 times of the logs.
#[derive(Clone, Copy, Debug)]
pub enum Fraction {
    /// Milliseconds, as in the access log.
    Millis,
    /// Microseconds, as in the process log.
    Micros,
}

/// How the logs write times: with the pattern of `log.time_format`, or as RFC 3339 without one,
/// in the time zone of `log.time_zone`. The default writes RFC 3339 in UTC.
#[derive(Clone, Debug, Default)]
pub struct LogTime {
    /// The pattern, if one is set.
    format: Option<TimeFormat>,
    /// The time zone.
    zone: TimeZone,
}

impl LogTime {
    /// Takes the time format and the time zone of `settings`.
    pub fn new(settings: &LogSettings) -> Self {
        Self {
            format: settings.time_format.clone(),
            zone: settings.time_zone,
        }
    }

    /// Writes `time` with the pattern, or without one as RFC 3339 with `fraction` digits of the
    /// second, such as `2026-10-29T08:30:00.000Z` or `2026-10-29T16:30:00.000+08:00`.
    pub fn write(
        &self,
        out: &mut impl fmt::Write,
        time: SystemTime,
        fraction: Fraction,
    ) -> fmt::Result {
        let utc = DateTime::<Utc>::from(time);
        match self.zone {
            TimeZone::Utc => self.write_in(out, utc, fraction),
            TimeZone::Local => self.write_in(out, utc.with_timezone(&Local), fraction),
        }
    }

    /// Writes `time` in the layout of the common log format whatever the pattern, in the time
    /// zone, such as `29/Oct/2026:16:30:00 +0800`.
    pub fn write_common_log(&self, out: &mut impl fmt::Write, time: SystemTime) -> fmt::Result {
        let utc = DateTime::<Utc>::from(time);
        match self.zone {
            TimeZone::Utc => write!(out, "{}", utc.format(COMMON_LOG)),
            TimeZone::Local => write!(out, "{}", utc.with_timezone(&Local).format(COMMON_LOG)),
        }
    }

    /// Writes `time`, already in the time zone, with the pattern or as RFC 3339.
    fn write_in<Zone: chrono::TimeZone>(
        &self,
        out: &mut impl fmt::Write,
        time: DateTime<Zone>,
        fraction: Fraction,
    ) -> fmt::Result
    where
        Zone::Offset: fmt::Display,
    {
        match &self.format {
            Some(format) => write!(out, "{}", time.format_with_items(format.items().iter())),
            None => {
                let digits = match fraction {
                    Fraction::Millis => SecondsFormat::Millis,
                    Fraction::Micros => SecondsFormat::Micros,
                };
                out.write_str(&time.to_rfc3339_opts(digits, true))
            }
        }
    }
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

    /// Returns what `time` writes for `at` with `fraction`.
    fn written(time: &LogTime, at: SystemTime, fraction: Fraction) -> String {
        let mut out = String::new();
        time.write(&mut out, at, fraction).unwrap();
        out
    }

    /// Returns what `time` writes for `at` in the common log format.
    fn common_log(time: &LogTime, at: SystemTime) -> String {
        let mut out = String::new();
        time.write_common_log(&mut out, at).unwrap();
        out
    }

    /// Without a pattern the logs write RFC 3339 in UTC, to the millisecond or the microsecond;
    /// a pattern takes its place.
    #[test]
    fn writes_log_times() {
        let time = at(1_761_696_000_123) + Duration::from_micros(456);
        let default = LogTime::default();
        assert_eq!(
            written(&default, time, Fraction::Millis),
            "2025-10-29T00:00:00.123Z"
        );
        assert_eq!(
            written(&default, time, Fraction::Micros),
            "2025-10-29T00:00:00.123456Z"
        );
        let settings = LogSettings {
            time_format: Some("%Y/%m/%d %H:%M:%S%.3f %z".parse().unwrap()),
            ..LogSettings::default()
        };
        let pattern = LogTime::new(&settings);
        for fraction in [Fraction::Millis, Fraction::Micros] {
            assert_eq!(
                written(&pattern, time, fraction),
                "2025/10/29 00:00:00.123 +0000"
            );
        }
    }

    /// The common log format writes the day first, the month by name and the zone, whatever
    /// the pattern.
    #[test]
    fn writes_common_log_times() {
        let default = LogTime::default();
        assert_eq!(
            common_log(&default, UNIX_EPOCH),
            "01/Jan/1970:00:00:00 +0000"
        );
        assert_eq!(
            common_log(&default, at(951_782_400_000)),
            "29/Feb/2000:00:00:00 +0000"
        );
        assert_eq!(
            common_log(&default, at(1_700_000_000_123)),
            "14/Nov/2023:22:13:20 +0000"
        );
        assert_eq!(
            common_log(&default, at(4_102_444_799_999)),
            "31/Dec/2099:23:59:59 +0000"
        );
        let settings = LogSettings {
            time_format: Some("%s".parse().unwrap()),
            ..LogSettings::default()
        };
        assert_eq!(
            common_log(&LogTime::new(&settings), at(1_700_000_000_123)),
            "14/Nov/2023:22:13:20 +0000"
        );
    }
}
