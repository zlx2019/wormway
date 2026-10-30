//! Sizes written as strings, such as `"10MiB"`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A size in bytes in the configuration, written as an integer and a unit, such as `"512KiB"`
/// or `"10MiB"`. The units are `B`, `KiB`, `MiB` and `GiB`, each 1024 times the one before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ByteSize(u64);

/// Units from the largest to the smallest, with their size in bytes.
const UNITS: [(&str, u64); 4] = [
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];

impl ByteSize {
    /// Creates a size of `bytes` bytes.
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// Returns the size in bytes.
    pub const fn bytes(self) -> u64 {
        self.0
    }
}

impl FromStr for ByteSize {
    type Err = ParseByteSizeError;

    /// Parses an integer followed by a unit.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || ParseByteSizeError::Invalid(text.to_owned());
        let digits = text
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len());
        let (number, unit) = text.split_at(digits);
        let unit_bytes = UNITS
            .iter()
            .find(|(name, _)| *name == unit)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(invalid)?;
        if number.is_empty() {
            return Err(invalid());
        }
        // A non-empty run of ASCII digits only fails to parse when it overflows.
        number
            .parse::<u64>()
            .ok()
            .and_then(|count| count.checked_mul(unit_bytes))
            .map(Self)
            .ok_or_else(|| ParseByteSizeError::TooLarge(text.to_owned()))
    }
}

impl fmt::Display for ByteSize {
    /// Writes the size in the largest unit that divides it, such as `10MiB` or `1536B`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (unit, bytes) = UNITS
            .iter()
            .find(|(_, bytes)| self.0.is_multiple_of(*bytes) && self.0 >= *bytes)
            .unwrap_or(&("B", 1));
        write!(f, "{}{unit}", self.0 / bytes)
    }
}

impl TryFrom<String> for ByteSize {
    type Error = ParseByteSizeError;

    /// Parses the string, see [`ByteSize`] for the format.
    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<ByteSize> for String {
    /// Formats the size, see the [`Display`](fmt::Display) implementation.
    fn from(size: ByteSize) -> Self {
        size.to_string()
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ByteSize {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ByteSize".into()
    }

    /// An integer and a unit; keep the units in sync with `UNITS`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "pattern": "^[0-9]+(B|KiB|MiB|GiB)$" })
    }
}

/// Error for text that is not a valid [`ByteSize`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseByteSizeError {
    /// The text is not an integer followed by a unit.
    #[error(
        "invalid size {0:?}, expected an integer and a unit (B, KiB, MiB or GiB) such as \"10MiB\""
    )]
    Invalid(String),
    /// The size does not fit in 64 bits.
    #[error("size {0:?} is too large")]
    TooLarge(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `text` and returns the result in bytes.
    fn bytes(text: &str) -> u64 {
        text.parse::<ByteSize>().unwrap().bytes()
    }

    /// Every unit is 1024 times the one before.
    #[test]
    fn parses_units() {
        assert_eq!(bytes("0B"), 0);
        assert_eq!(bytes("100B"), 100);
        assert_eq!(bytes("512KiB"), 512 * 1024);
        assert_eq!(bytes("10MiB"), 10 * 1024 * 1024);
        assert_eq!(bytes("2GiB"), 2 * 1024 * 1024 * 1024);
    }

    /// Missing numbers or units, other units, signs, fractions, spaces and several parts are
    /// rejected.
    #[test]
    fn rejects_malformed_text() {
        for text in [
            "", "10", "MiB", "10mib", "10MB", "10M", "10m", "-1B", "+1B", "1.5MiB", "10 MiB",
            " 10MiB", "1MiB1KiB",
        ] {
            assert_eq!(
                text.parse::<ByteSize>(),
                Err(ParseByteSizeError::Invalid(text.to_owned())),
                "{text:?}"
            );
        }
    }

    /// Sizes beyond 64 bits are reported as too large.
    #[test]
    fn rejects_overflow() {
        for text in ["18446744073709551616B", "17179869184GiB"] {
            assert_eq!(
                text.parse::<ByteSize>(),
                Err(ParseByteSizeError::TooLarge(text.to_owned())),
                "{text:?}"
            );
        }
    }

    /// Formatting uses the largest unit that divides the size and parses back to it.
    #[test]
    fn formats_and_round_trips() {
        for (text, expected) in [
            ("0B", "0B"),
            ("1024B", "1KiB"),
            ("1536B", "1536B"),
            ("10240KiB", "10MiB"),
            ("3072MiB", "3GiB"),
        ] {
            let size: ByteSize = text.parse().unwrap();
            assert_eq!(size.to_string(), expected);
            assert_eq!(expected.parse::<ByteSize>().unwrap(), size);
        }
    }
}
