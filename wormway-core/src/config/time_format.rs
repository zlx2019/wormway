//! Time formats of the logs, written as strftime patterns such as `"%Y-%m-%d %H:%M:%S"`.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use chrono::format::{Item, StrftimeItems};
use serde::{Deserialize, Serialize};

/// How the logs write times: a strftime pattern as chrono reads it, such as
/// `"%Y-%m-%d %H:%M:%S%.3f"`, where `%.3f` adds the milliseconds and `%z` the offset from UTC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TimeFormat {
    /// The pattern as written.
    pattern: String,
    /// The pattern, parsed once.
    items: Arc<[Item<'static>]>,
}

impl TimeFormat {
    /// Returns the pattern as written.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Returns the parsed pattern.
    pub(crate) fn items(&self) -> &[Item<'static>] {
        &self.items
    }
}

impl FromStr for TimeFormat {
    type Err = InvalidTimeFormat;

    /// Parses a pattern, which must not be empty.
    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidTimeFormat(pattern.to_owned());
        if pattern.is_empty() {
            return Err(invalid());
        }
        let items = StrftimeItems::new(pattern)
            .parse_to_owned()
            .map_err(|_| invalid())?;
        Ok(Self {
            pattern: pattern.to_owned(),
            items: items.into(),
        })
    }
}

impl TryFrom<String> for TimeFormat {
    type Error = InvalidTimeFormat;

    /// Parses the pattern, see [`TimeFormat`].
    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        pattern.parse()
    }
}

impl From<TimeFormat> for String {
    /// Returns the pattern as written.
    fn from(format: TimeFormat) -> Self {
        format.pattern
    }
}

impl fmt::Display for TimeFormat {
    /// Writes the pattern as written.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TimeFormat {
    /// Inlined: a named definition would add nothing to a plain string.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TimeFormat".into()
    }

    /// A non-empty string; chrono checks the fields.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "minLength": 1 })
    }
}

/// Error for text that is not a valid [`TimeFormat`].
#[derive(Debug, thiserror::Error)]
#[error("invalid time format {0:?}: expected strftime fields such as \"%Y-%m-%d %H:%M:%S%.3f\"")]
pub struct InvalidTimeFormat(String);
