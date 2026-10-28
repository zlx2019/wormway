//! Durations written as strings, such as `"30s"` or `"1m30s"`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A duration in the configuration, written as one or more `<integer><unit>` parts such as
/// `"30s"`, `"250ms"` or `"1h30m"`. The units are `ms`, `s`, `m`, `h` and `d`.
///
/// The precision is one millisecond. [`Duration::get`] returns the standard library value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Duration(std::time::Duration);

/// Units from the largest to the smallest, with their length in milliseconds.
const UNITS: [(&str, u64); 5] = [
    ("d", 86_400_000),
    ("h", 3_600_000),
    ("m", 60_000),
    ("s", 1_000),
    ("ms", 1),
];

impl Duration {
    /// Creates a duration of `secs` seconds.
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    /// Returns the standard library value.
    pub const fn get(self) -> std::time::Duration {
        self.0
    }
}

impl FromStr for Duration {
    type Err = ParseDurationError;

    /// Parses `<integer><unit>` parts and adds them up. Every part needs a unit.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || ParseDurationError::Invalid(text.to_owned());
        if text.is_empty() {
            return Err(invalid());
        }
        let mut total: u64 = 0;
        let mut rest = text;
        while !rest.is_empty() {
            let (number, unit, tail) = split_part(rest);
            let unit_millis = UNITS
                .iter()
                .find(|(name, _)| *name == unit)
                .map(|(_, millis)| *millis)
                .ok_or_else(invalid)?;
            if number.is_empty() {
                return Err(invalid());
            }
            // A non-empty run of ASCII digits only fails to parse when it overflows.
            total = number
                .parse::<u64>()
                .ok()
                .and_then(|n| n.checked_mul(unit_millis))
                .and_then(|millis| total.checked_add(millis))
                .ok_or_else(|| ParseDurationError::TooLarge(text.to_owned()))?;
            rest = tail;
        }
        Ok(Self(std::time::Duration::from_millis(total)))
    }
}

/// Splits `text` into its leading digits, the unit after them and the remaining text.
fn split_part(text: &str) -> (&str, &str, &str) {
    let unit_start = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let unit_end = text[unit_start..]
        .find(|c: char| c.is_ascii_digit())
        .map_or(text.len(), |i| unit_start + i);
    (
        &text[..unit_start],
        &text[unit_start..unit_end],
        &text[unit_end..],
    )
}

impl fmt::Display for Duration {
    /// Writes the duration with the largest units first, such as `1m30s`. Zero is `0s`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0.as_millis();
        if rest == 0 {
            return f.write_str("0s");
        }
        for (unit, millis) in UNITS {
            let count = rest / u128::from(millis);
            if count > 0 {
                write!(f, "{count}{unit}")?;
                rest %= u128::from(millis);
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for Duration {
    type Error = ParseDurationError;

    /// Parses the string, see [`Duration`] for the format.
    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<Duration> for String {
    /// Formats the duration, see the [`Display`](fmt::Display) implementation.
    fn from(duration: Duration) -> Self {
        duration.to_string()
    }
}

impl From<Duration> for std::time::Duration {
    /// Returns the standard library value.
    fn from(duration: Duration) -> Self {
        duration.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Duration {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Duration".into()
    }

    /// A string of `<integer><unit>` parts; keep the units in sync with `UNITS`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "pattern": "^([0-9]+(ms|s|m|h|d))+$" })
    }
}

/// Error for text that is not a valid [`Duration`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseDurationError {
    /// The text does not follow the `<integer><unit>` format.
    #[error(
        "invalid duration {0:?}, expected an integer and a unit (ms, s, m, h or d) such as \"30s\" or \"1m30s\""
    )]
    Invalid(String),
    /// The total does not fit in 64 bits of milliseconds.
    #[error("duration {0:?} is too large")]
    TooLarge(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `text` and returns the result in milliseconds.
    fn millis(text: &str) -> u128 {
        text.parse::<Duration>().unwrap().get().as_millis()
    }

    /// Single parts, combined parts and repeated units all add up.
    #[test]
    fn parses_parts() {
        assert_eq!(millis("0s"), 0);
        assert_eq!(millis("250ms"), 250);
        assert_eq!(millis("30s"), 30_000);
        assert_eq!(millis("1m30s"), 90_000);
        assert_eq!(millis("1h30m"), 5_400_000);
        assert_eq!(millis("1d"), 86_400_000);
        assert_eq!(millis("1s1s"), 2_000);
    }

    /// Missing numbers or units, unknown units, signs, fractions and spaces are rejected.
    #[test]
    fn rejects_malformed_text() {
        for text in [
            "", "30", "s", "1m30", "30x", "-1s", "+1s", "1.5s", "30 s", " 30s", "1S",
        ] {
            assert_eq!(
                text.parse::<Duration>(),
                Err(ParseDurationError::Invalid(text.to_owned())),
                "{text:?}"
            );
        }
    }

    /// Values beyond 64 bits of milliseconds are reported as too large.
    #[test]
    fn rejects_overflow() {
        for text in [
            "18446744073709551616ms",
            "213503982335d",
            "18446744073709551615ms1ms",
        ] {
            assert_eq!(
                text.parse::<Duration>(),
                Err(ParseDurationError::TooLarge(text.to_owned())),
                "{text:?}"
            );
        }
    }

    /// Formatting uses the largest units first and parses back to the same value.
    #[test]
    fn formats_and_round_trips() {
        for (text, expected) in [
            ("0ms", "0s"),
            ("90s", "1m30s"),
            ("1500ms", "1s500ms"),
            ("25h", "1d1h"),
        ] {
            let duration: Duration = text.parse().unwrap();
            assert_eq!(duration.to_string(), expected);
            assert_eq!(expected.parse::<Duration>().unwrap(), duration);
        }
    }
}
