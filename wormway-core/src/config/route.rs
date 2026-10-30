//! Routes: which requests of the HTTP listeners go to which upstream.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::http::is_header_value;
use super::{
    Action, ByteSize, HeaderName, HeaderRules, Method, Name, RateLimit, Redirect, Respond, Rewrite,
    RouteTimeouts,
};

/// A rule of the HTTP listeners: the requests it matches go to its upstream, or get a redirect
/// or a fixed response. Exactly one of `upstream`, `redirect` and `respond` is set.
///
/// When several routes match a request, they are compared in this order, and the first
/// difference decides:
///
/// 1. the higher `priority`;
/// 2. an exact host, then a wildcard host, then any host;
/// 3. an exact path, then a regular expression, then a path prefix, longer prefixes first, then
///    any path;
/// 4. a route with methods before one without;
/// 5. the route with more header conditions;
/// 6. the route name in alphabetical order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// HTTP listeners whose requests the route sees. Without it, every HTTP listener.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Name>,
    /// Precedence over the other routes that match a request: higher first. Default: 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: i32,
    /// Which requests the route takes. Without it, every request.
    #[serde(default, skip_serializing_if = "RouteMatch::is_any")]
    pub r#match: RouteMatch,
    /// Upstream that serves the requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Name>,
    /// A redirect to answer the requests with, such as
    /// `{ to = "https://{host}{uri}", status = 301 }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
    /// A fixed response to answer the requests with, such as
    /// `{ status = 503, body = "down for maintenance" }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub respond: Option<Respond>,
    /// Changes to the path of the requests sent to the upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite: Option<Rewrite>,
    /// Changes to the headers of the requests sent to the upstream. They come after the
    /// `X-Forwarded-*`, `X-Real-IP` and `X-Request-Id` headers that Wormway sets, so they can
    /// change or remove those too.
    #[serde(default, skip_serializing_if = "HeaderRules::is_empty")]
    pub request_headers: HeaderRules,
    /// Changes to the headers of the responses, whether they come from the upstream or from the
    /// route.
    #[serde(default, skip_serializing_if = "HeaderRules::is_empty")]
    pub response_headers: HeaderRules,
    /// Compress responses with gzip, Brotli or zstd, the first that the client accepts, when
    /// their type is text-like. Streams of server-sent events and gRPC are left alone. Default:
    /// `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<bool>,
    /// Write the requests of the route to the access log, when `log.access` turns it on.
    /// Default: `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<bool>,
    /// Time limits of the requests to the upstream, in place of those of the upstream, such as
    /// `{ read = "5m" }` for slow reports.
    #[serde(default, skip_serializing_if = "RouteTimeouts::is_default")]
    pub timeouts: RouteTimeouts,
    /// How many requests each client, or another key, may make per period, such as
    /// `{ requests = 100, per = "1s" }`; more are answered with 429.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// The most requests of the route in progress at once; more are answered with 503 right
    /// away.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_limit: Option<u32>,
    /// The largest request body, such as `"10MiB"`; larger ones are answered with 413. Without
    /// it, any size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_size: Option<ByteSize>,
}

impl Route {
    /// Returns what the route does, or `None` unless exactly one of `upstream`, `redirect` and
    /// `respond` is set, which validation rules out.
    pub fn action(&self) -> Option<Action<'_>> {
        match (&self.upstream, &self.redirect, &self.respond) {
            (Some(upstream), None, None) => Some(Action::Upstream(upstream)),
            (None, Some(redirect), None) => Some(Action::Redirect(redirect)),
            (None, None, Some(respond)) => Some(Action::Respond(respond)),
            _ => None,
        }
    }

    /// Whether responses are compressed.
    pub fn compress(&self) -> bool {
        self.compress.unwrap_or(false)
    }

    /// Whether the requests go to the access log.
    pub fn access_log(&self) -> bool {
        self.access_log.unwrap_or(true)
    }
}

/// Whether a priority is the default one, which is not written out.
fn is_zero(priority: &i32) -> bool {
    *priority == 0
}

/// Conditions on a request. A request matches when it meets every condition that is set.
///
/// Paths are compared after normalization: every `%XX` decoded, `.` and `..` segments resolved
/// and repeated slashes merged, so that `/a/../admin/` and `/admin%2F` both count as paths
/// under `/admin/`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    /// Host names, such as `example.com`, or `*.example.com` for one label in front of
    /// `example.com`. Without it, any host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostPattern>,
    /// Paths: a prefix such as `"/api/"`, an exact path such as `{ exact = "/" }`, or a regular
    /// expression such as `{ regex = "^/v[0-9]+/" }`. Without it, any path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathPattern>,
    /// Methods, such as `["GET", "HEAD"]`. Without it, any method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<Method>,
    /// Conditions on headers, by name: a value that one of the values of the header must equal,
    /// `true` for a header that must be present, or `false` for one that must be absent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<HeaderName, HeaderCondition>,
}

impl RouteMatch {
    /// Whether no condition is set, so that every request matches.
    pub fn is_any(&self) -> bool {
        self.hosts.is_empty()
            && self.paths.is_empty()
            && self.methods.is_empty()
            && self.headers.is_empty()
    }
}

/// A path condition of a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathPattern {
    /// Paths that start with this text, written as a string. A prefix compares characters, not
    /// path segments, so `/api` also matches `/apis`.
    Prefix(String),
    /// This path only, written as `{ exact = "/" }`.
    Exact(String),
    /// Paths in which this regular expression finds a match, written as `{ regex = "..." }`. It
    /// is not anchored: `^` and `$` tie it to the start and the end of the path.
    Regex(PathRegex),
}

/// The table form of a path condition.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathTable {
    /// An exact path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exact: Option<String>,
    /// A regular expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    regex: Option<PathRegex>,
}

impl Serialize for PathPattern {
    /// Writes a prefix as a string and the other kinds as a table.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let table = match self {
            Self::Prefix(prefix) => return serializer.serialize_str(prefix),
            Self::Exact(path) => PathTable {
                exact: Some(path.clone()),
                regex: None,
            },
            Self::Regex(regex) => PathTable {
                exact: None,
                regex: Some(regex.clone()),
            },
        };
        table.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PathPattern {
    /// Reads either form.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(PathVisitor)
    }
}

/// Reads a path condition from a string or a table.
struct PathVisitor;

impl<'de> Visitor<'de> for PathVisitor {
    type Value = PathPattern;

    /// Describes both forms for error messages.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a path prefix such as \"/api/\", or a table with exact or regex")
    }

    /// The prefix form.
    fn visit_str<E: de::Error>(self, text: &str) -> Result<PathPattern, E> {
        Ok(PathPattern::Prefix(text.to_owned()))
    }

    /// The table form, with exactly one kind.
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<PathPattern, A::Error> {
        match PathTable::deserialize(MapAccessDeserializer::new(map))? {
            PathTable {
                exact: Some(path),
                regex: None,
            } => Ok(PathPattern::Exact(path)),
            PathTable {
                exact: None,
                regex: Some(regex),
            } => Ok(PathPattern::Regex(regex)),
            _ => Err(de::Error::custom(
                "expected exactly one of `exact` and `regex`",
            )),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PathPattern {
    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PathPattern".into()
    }

    /// A prefix, or a table with one kind.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A path prefix such as \"/api/\", an exact path such as { exact = \"/\" }, or a regular expression such as { regex = \"^/v[0-9]+/\" }.",
            "anyOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "properties": {
                        "exact": { "description": "This path only.", "type": "string" }
                    },
                    "required": ["exact"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "regex": {
                            "description": "Paths in which this regular expression finds a match; ^ and $ anchor it.",
                            "type": "string"
                        }
                    },
                    "required": ["regex"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

/// A regular expression over request paths, in the syntax of the Rust `regex` crate. It runs in
/// time linear in the length of the path, whatever the expression.
#[derive(Clone, Debug)]
pub struct PathRegex(regex::bytes::Regex);

impl PathRegex {
    /// Returns the expression as written.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether the expression finds a match in `path`, a normalized path that may hold bytes
    /// that are not UTF-8.
    pub fn is_match(&self, path: &[u8]) -> bool {
        self.0.is_match(path)
    }
}

impl PartialEq for PathRegex {
    /// Compares the expressions as written.
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for PathRegex {}

impl FromStr for PathRegex {
    type Err = InvalidRegex;

    /// Compiles the expression.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        regex::bytes::Regex::new(s)
            .map(Self)
            .map_err(|error| InvalidRegex(error.to_string()))
    }
}

impl Serialize for PathRegex {
    /// Writes the expression as written.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PathRegex {
    /// Reads and compiles the expression, so that a mistake is reported where it is written.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// Error for a regular expression that does not compile, with the message of the compiler.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid regular expression: {0}")]
pub struct InvalidRegex(pub String);

/// A condition on a request header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderCondition {
    /// One of the values of the header equals this text, written as a string. The comparison
    /// is exact, case included.
    Equals(String),
    /// The header is present, written as `true`, or absent, written as `false`.
    Present(bool),
}

impl Serialize for HeaderCondition {
    /// Writes the value or the boolean.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Equals(value) => serializer.serialize_str(value),
            Self::Present(present) => serializer.serialize_bool(*present),
        }
    }
}

impl<'de> Deserialize<'de> for HeaderCondition {
    /// Reads either form.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(HeaderConditionVisitor)
    }
}

/// Reads a header condition from a string or a boolean.
struct HeaderConditionVisitor;

impl<'de> Visitor<'de> for HeaderConditionVisitor {
    type Value = HeaderCondition;

    /// Describes both forms for error messages.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a header value, or true or false for a header that is present or absent")
    }

    /// A value that the header must have.
    fn visit_str<E: de::Error>(self, text: &str) -> Result<HeaderCondition, E> {
        if is_header_value(text) {
            Ok(HeaderCondition::Equals(text.to_owned()))
        } else {
            Err(E::custom(format!(
                "invalid header value {text:?}, expected visible ASCII characters, spaces and tabs"
            )))
        }
    }

    /// Whether the header must be present.
    fn visit_bool<E: de::Error>(self, present: bool) -> Result<HeaderCondition, E> {
        Ok(HeaderCondition::Present(present))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for HeaderCondition {
    /// Inlined: a named definition would add nothing to two plain types.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HeaderCondition".into()
    }

    /// A value, or a boolean.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "anyOf": [{ "type": "string" }, { "type": "boolean" }]
        })
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

    /// Reads the conditions of a TOML route table.
    fn conditions(text: &str) -> Result<RouteMatch, toml::de::Error> {
        toml::from_str::<Route>(&format!("upstream = \"app\"\n{text}")).map(|route| route.r#match)
    }

    /// Paths come as prefixes, exact paths and regular expressions, and are written back in
    /// the form they were read.
    #[test]
    fn reads_and_writes_path_kinds() {
        let read = conditions(
            r#"match = { paths = ["/api/", { exact = "/" }, { regex = "^/v[0-9]+/" }] }"#,
        )
        .unwrap();
        assert_eq!(read.paths[0], PathPattern::Prefix("/api/".to_owned()));
        assert_eq!(read.paths[1], PathPattern::Exact("/".to_owned()));
        let PathPattern::Regex(regex) = &read.paths[2] else {
            panic!("expected a regex, got {:?}", read.paths[2]);
        };
        assert_eq!(regex.as_str(), "^/v[0-9]+/");
        assert!(regex.is_match(b"/v2/users"));
        assert!(!regex.is_match(b"/api/v2/"));

        let json = serde_json::to_string(&read).unwrap();
        assert_eq!(
            json,
            r#"{"paths":["/api/",{"exact":"/"},{"regex":"^/v[0-9]+/"}]}"#
        );
        assert_eq!(serde_json::from_str::<RouteMatch>(&json).unwrap(), read);
    }

    /// A table needs exactly one kind, and regular expressions must compile.
    #[test]
    fn rejects_malformed_paths() {
        for text in [
            r#"match = { paths = [{}] }"#,
            r#"match = { paths = [{ exact = "/", regex = "/" }] }"#,
            r#"match = { paths = [{ prefix = "/" }] }"#,
            r#"match = { paths = [3] }"#,
        ] {
            assert!(conditions(text).is_err(), "{text}");
        }
        let error = conditions(r#"match = { paths = [{ regex = "^/v[0-9+/" }] }"#).unwrap_err();
        assert!(
            error.message().starts_with("invalid regular expression"),
            "{error}"
        );
        assert!(error.span().is_some(), "{error}");
    }

    /// Methods are uppercased; header conditions are values or booleans, and values must be
    /// valid header values.
    #[test]
    fn reads_methods_and_headers() {
        let read = conditions(
            r#"match = { methods = ["get", "POST"], headers = { "X-Canary" = "1", Authorization = true, "X-Debug" = false } }"#,
        )
        .unwrap();
        let methods: Vec<&str> = read.methods.iter().map(Method::as_str).collect();
        assert_eq!(methods, ["GET", "POST"]);
        let headers: Vec<(&str, &HeaderCondition)> = read
            .headers
            .iter()
            .map(|(name, condition)| (name.as_str(), condition))
            .collect();
        assert_eq!(
            headers,
            [
                ("Authorization", &HeaderCondition::Present(true)),
                ("X-Canary", &HeaderCondition::Equals("1".to_owned())),
                ("X-Debug", &HeaderCondition::Present(false)),
            ]
        );
        assert_eq!(
            serde_json::to_string(&read.headers).unwrap(),
            r#"{"Authorization":true,"X-Canary":"1","X-Debug":false}"#
        );

        for text in [
            r#"match = { headers = { "X-Canary" = "a\nb" } }"#,
            r#"match = { headers = { "X Canary" = "1" } }"#,
            r#"match = { headers = { "X-Canary" = 1 } }"#,
            r#"match = { methods = ["GET POST"] }"#,
        ] {
            assert!(conditions(text).is_err(), "{text}");
        }
    }

    /// Actions and modifiers are read, written back in the same form, and the action is the
    /// one field of upstream, redirect and respond that is set.
    #[test]
    fn reads_and_writes_actions_and_modifiers() {
        let route: Route = toml::from_str(
            r#"
            upstream = "api"
            rewrite = { strip_prefix = "/v1", add_prefix = "/api" }
            request_headers = { remove = ["X-Debug"], set = { "X-Env" = "prod" }, add = { "X-Tag" = "a" } }
            response_headers = { set = { "Strict-Transport-Security" = "max-age=63072000" } }
            compress = true
            "#,
        )
        .unwrap();
        let api: Name = "api".parse().unwrap();
        assert_eq!(route.action(), Some(Action::Upstream(&api)));
        assert!(route.compress());
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(
            json,
            r#"{"upstream":"api","rewrite":{"strip_prefix":"/v1","add_prefix":"/api"},"request_headers":{"remove":["X-Debug"],"set":{"X-Env":"prod"},"add":{"X-Tag":"a"}},"response_headers":{"set":{"Strict-Transport-Security":"max-age=63072000"}},"compress":true}"#
        );
        assert_eq!(serde_json::from_str::<Route>(&json).unwrap(), route);
        let toml = toml::to_string(&route).unwrap();
        assert_eq!(toml::from_str::<Route>(&toml).unwrap(), route);

        let redirect: Route = toml::from_str(r#"redirect = { to = "/new" }"#).unwrap();
        assert_eq!(
            redirect.action(),
            Some(Action::Redirect(&Redirect {
                to: "/new".to_owned(),
                status: None,
            }))
        );
        assert!(!redirect.compress());
        let both: Route = toml::from_str("upstream = \"api\"\nrespond = { status = 200 }").unwrap();
        assert_eq!(both.action(), None);
        assert_eq!(Route::default().action(), None);

        let bad_value = r#"response_headers = { set = { "X-A" = "a\nb" } }"#;
        let error = toml::from_str::<Route>(bad_value).unwrap_err();
        assert!(
            error.message().starts_with("invalid header value"),
            "{error}"
        );
    }

    /// Limits are read and written back in the same form; sizes need a unit.
    #[test]
    fn reads_and_writes_limits() {
        let route: Route = toml::from_str(
            r#"
            upstream = "api"
            rate_limit = { requests = 100, per = "1s" }
            concurrency_limit = 50
            max_body_size = "10MiB"
            "#,
        )
        .unwrap();
        let rate_limit = route.rate_limit.as_ref().unwrap();
        assert_eq!(
            (rate_limit.requests, rate_limit.per.get().as_secs()),
            (100, 1)
        );
        assert_eq!(route.concurrency_limit, Some(50));
        assert_eq!(route.max_body_size.map(ByteSize::bytes), Some(10 << 20));
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(
            json,
            r#"{"upstream":"api","rate_limit":{"requests":100,"per":"1s"},"concurrency_limit":50,"max_body_size":"10MiB"}"#
        );
        assert_eq!(serde_json::from_str::<Route>(&json).unwrap(), route);
        let toml = toml::to_string(&route).unwrap();
        assert_eq!(toml::from_str::<Route>(&toml).unwrap(), route);

        let error =
            toml::from_str::<Route>("upstream = \"api\"\nmax_body_size = 1024").unwrap_err();
        assert!(error.message().contains("invalid type"), "{error}");
    }
}
