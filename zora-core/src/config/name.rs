//! Names of configuration entities.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The name of a configuration entity, such as a listener or a certificate.
///
/// A name is 1 to 64 characters from `a-z`, `0-9`, `_` and `-`. Names key the entity tables of
/// the configuration and are used in references between entities and in Admin API paths.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Name {
    /// Maximum length in characters.
    pub const MAX_LEN: usize = 64;

    /// Returns the name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = InvalidName;

    /// Accepts the string if it follows the naming rules.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let allowed = |b: u8| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-');
        if !value.is_empty() && value.len() <= Self::MAX_LEN && value.bytes().all(allowed) {
            Ok(Self(value))
        } else {
            Err(InvalidName(value))
        }
    }
}

impl FromStr for Name {
    type Err = InvalidName;

    /// Parses a name, see [`Name`] for the rules.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<Name> for String {
    /// Returns the inner string.
    fn from(name: Name) -> Self {
        name.0
    }
}

impl Borrow<str> for Name {
    /// Lets maps keyed by `Name` be queried with a `&str`.
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    /// Writes the name as is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Name {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Name".into()
    }

    /// A string matching the naming rules; keep the pattern in sync with `Name::MAX_LEN`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "pattern": "^[a-z0-9_-]{1,64}$" })
    }
}

/// Error for a string that is not a valid [`Name`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid name {0:?}, use 1 to 64 characters from a-z, 0-9, _ and -")]
pub struct InvalidName(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    /// Names made of the allowed characters, up to the length limit, are accepted.
    #[test]
    fn accepts_valid_names() {
        for name in ["a", "web", "web-secure_2", &"x".repeat(Name::MAX_LEN)] {
            assert_eq!(name.parse::<Name>().unwrap().as_str(), name);
        }
    }

    /// Empty, overlong, uppercase and punctuated names are rejected.
    #[test]
    fn rejects_invalid_names() {
        let too_long = "x".repeat(Name::MAX_LEN + 1);
        for name in ["", "Web", "web.secure", "web secure", "名字", &too_long] {
            assert_eq!(name.parse::<Name>(), Err(InvalidName(name.to_owned())));
        }
    }
}
