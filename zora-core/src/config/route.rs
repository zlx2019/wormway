//! Routes: which requests of the HTTP listeners go to which upstream.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::Name;

/// A rule of the HTTP listeners: the requests it matches go to its upstream.
///
/// When several routes match a request, the most specific one wins: an exact host before a
/// wildcard host before any host, then the longest path prefix, then the route name in
/// alphabetical order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// HTTP listeners whose requests the route sees. Without it, every HTTP listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Name>,
    /// Which requests the route takes. Without it, every request.
    #[serde(default, skip_serializing_if = "RouteMatch::is_any")]
    pub r#match: RouteMatch,
    /// Upstream that serves the requests.
    pub upstream: Name,
}

/// Conditions on a request. A request matches when it meets every condition that is set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    /// Host names, such as `example.com`, or `*.example.com` for one label in front of
    /// `example.com`. Without it, any host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostPattern>,
    /// Path prefixes, such as `/api/`. A prefix compares characters, not path segments, so `/api`
    /// also matches `/apis`. Without it, any path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

impl RouteMatch {
    /// Whether no condition is set, so that every request matches.
    pub fn is_any(&self) -> bool {
        self.hosts.is_empty() && self.paths.is_empty()
    }
}

/// A host name that a route matches: exact, such as `example.com`, or with a wildcard first
/// label, such as `*.example.com`.
///
/// Host names are case-insensitive, so patterns are kept in lowercase. A wildcard stands for
/// exactly one label: `*.example.com` matches `a.example.com` but neither `example.com` nor
/// `a.b.example.com`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostPattern(String);

impl HostPattern {
    /// Maximum length of the host name after `*.`, as in DNS.
    pub const MAX_LEN: usize = 253;

    /// Returns the pattern in lowercase.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the host name after `*.` of a wildcard pattern, such as `example.com`.
    pub fn wildcard_suffix(&self) -> Option<&str> {
        self.0.strip_prefix("*.")
    }
}

/// Whether `name` is a host name: labels of 1 to 63 characters from letters, digits, `-` and
/// `_`, separated by dots, with at most [`HostPattern::MAX_LEN`] characters in all. IPv4
/// addresses pass too.
fn is_host_name(name: &str) -> bool {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    name.len() <= HostPattern::MAX_LEN && name.split('.').all(label_ok)
}

impl TryFrom<String> for HostPattern {
    type Error = InvalidHostPattern;

    /// Accepts a host name with an optional `*.` in front, and lowercases it.
    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        if !is_host_name(value.strip_prefix("*.").unwrap_or(&value)) {
            return Err(InvalidHostPattern(value));
        }
        value.make_ascii_lowercase();
        Ok(Self(value))
    }
}

impl FromStr for HostPattern {
    type Err = InvalidHostPattern;

    /// Parses a pattern, see [`HostPattern`] for the rules.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<HostPattern> for String {
    /// Returns the pattern in lowercase.
    fn from(pattern: HostPattern) -> Self {
        pattern.0
    }
}

impl fmt::Display for HostPattern {
    /// Writes the pattern in lowercase.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for HostPattern {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HostPattern".into()
    }

    /// A host name with an optional `*.` in front; keep in sync with `is_host_name`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^(\\*\\.)?[A-Za-z0-9_-]{1,63}(\\.[A-Za-z0-9_-]{1,63})*$",
            "maxLength": 255
        })
    }
}

/// Error for a string that is not a valid [`HostPattern`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid host {0:?}, expected a host name such as \"example.com\" or \"*.example.com\"")]
pub struct InvalidHostPattern(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    /// Host names, IPv4 addresses and wildcards are accepted and lowercased.
    #[test]
    fn accepts_host_names_and_wildcards() {
        for (text, expected) in [
            ("example.com", "example.com"),
            ("API.Example.COM", "api.example.com"),
            ("*.example.com", "*.example.com"),
            ("*.Example.com", "*.example.com"),
            ("localhost", "localhost"),
            ("127.0.0.1", "127.0.0.1"),
            ("my_service.internal", "my_service.internal"),
        ] {
            assert_eq!(text.parse::<HostPattern>().unwrap().as_str(), expected);
        }
        let wildcard: HostPattern = "*.example.com".parse().unwrap();
        assert_eq!(wildcard.wildcard_suffix(), Some("example.com"));
        let exact: HostPattern = "example.com".parse().unwrap();
        assert_eq!(exact.wildcard_suffix(), None);
    }

    /// Empty labels, wildcards other than a whole first label, ports and other characters are
    /// rejected.
    #[test]
    fn rejects_malformed_patterns() {
        let long_label = format!("{}.com", "a".repeat(64));
        let too_long = vec!["a".repeat(63); 4].join(".") + ".com";
        for text in [
            "",
            "*",
            "*.",
            "a*.example.com",
            "a.*.example.com",
            "**.example.com",
            ".example.com",
            "example.com.",
            "example..com",
            "example.com:80",
            "[::1]",
            "exa mple.com",
            "例子.com",
            &long_label,
            &too_long,
        ] {
            assert_eq!(
                text.parse::<HostPattern>(),
                Err(InvalidHostPattern(text.to_owned())),
                "{text:?}"
            );
        }
    }
}
