//! HTTP names in the configuration: header names and methods.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Whether `text` is an HTTP token, the syntax of header names and methods: one or more letters,
/// digits and ``!#$%&'*+-.^_`|~``.
pub(crate) fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether `text` can be the value of a header: visible ASCII characters, spaces and tabs.
pub(crate) fn is_header_value(text: &str) -> bool {
    text.bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

/// The name of an HTTP header, such as `X-Request-Id`. Header names are case-insensitive; the
/// name keeps the case it is written in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeaderName(String);

impl HeaderName {
    /// Returns the name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HeaderName {
    type Error = InvalidHeaderName;

    /// Accepts an HTTP token.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_token(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidHeaderName(value))
        }
    }
}

impl FromStr for HeaderName {
    type Err = InvalidHeaderName;

    /// Parses a header name, see [`HeaderName`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<HeaderName> for String {
    /// Returns the name as written.
    fn from(name: HeaderName) -> Self {
        name.0
    }
}

impl fmt::Display for HeaderName {
    /// Writes the name as written.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error for a string that is not a valid [`HeaderName`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid header name {0:?}, expected letters, digits and characters such as - or _")]
pub struct InvalidHeaderName(pub String);

/// The value of an HTTP header: visible ASCII characters, spaces and tabs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeaderValue(String);

impl HeaderValue {
    /// Returns the value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HeaderValue {
    type Error = InvalidHeaderValue;

    /// Accepts visible ASCII characters, spaces and tabs.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_header_value(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidHeaderValue(value))
        }
    }
}

impl FromStr for HeaderValue {
    type Err = InvalidHeaderValue;

    /// Parses a header value, see [`HeaderValue`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<HeaderValue> for String {
    /// Returns the value.
    fn from(value: HeaderValue) -> Self {
        value.0
    }
}

impl fmt::Display for HeaderValue {
    /// Writes the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error for a string that is not a valid [`HeaderValue`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid header value {0:?}, expected visible ASCII characters, spaces and tabs")]
pub struct InvalidHeaderValue(pub String);

/// An HTTP request method, such as `GET`. Methods are case-sensitive and the standard ones are
/// in uppercase, so methods are kept in uppercase.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Method(String);

impl Method {
    /// Returns the method in uppercase.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Method {
    type Error = InvalidMethod;

    /// Accepts an HTTP token and uppercases it.
    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        if !is_token(&value) {
            return Err(InvalidMethod(value));
        }
        value.make_ascii_uppercase();
        Ok(Self(value))
    }
}

impl FromStr for Method {
    type Err = InvalidMethod;

    /// Parses a method, see [`Method`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<Method> for String {
    /// Returns the method in uppercase.
    fn from(method: Method) -> Self {
        method.0
    }
}

impl fmt::Display for Method {
    /// Writes the method in uppercase.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error for a string that is not a valid [`Method`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid method {0:?}, expected a method such as \"GET\"")]
pub struct InvalidMethod(pub String);

/// Schema of a string that is an HTTP token; keep in sync with `is_token`.
#[cfg(feature = "schema")]
fn token_schema() -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "pattern": "^[A-Za-z0-9!#$%&'*+.^_`|~-]+$"
    })
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for HeaderName {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HeaderName".into()
    }

    /// An HTTP token.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        token_schema()
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for HeaderValue {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "HeaderValue".into()
    }

    /// Visible ASCII characters, spaces and tabs; keep in sync with `is_header_value`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[\\t -~]*$"
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Method {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Method".into()
    }

    /// An HTTP token.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        token_schema()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Header names keep their case; methods are uppercased.
    #[test]
    fn accepts_tokens() {
        let name: HeaderName = "X-Request-Id".parse().unwrap();
        assert_eq!(name.as_str(), "X-Request-Id");
        let method: Method = "get".parse().unwrap();
        assert_eq!(method.as_str(), "GET");
        assert_eq!("PROPFIND".parse::<Method>().unwrap().as_str(), "PROPFIND");
    }

    /// Empty names, spaces, separators and characters beyond ASCII are rejected.
    #[test]
    fn rejects_other_characters() {
        for text in ["", "X Header", "X:Header", "X-Header\n", "Größe", "(x)"] {
            assert_eq!(
                text.parse::<HeaderName>(),
                Err(InvalidHeaderName(text.to_owned()))
            );
            assert_eq!(text.parse::<Method>(), Err(InvalidMethod(text.to_owned())));
        }
    }

    /// Header values are visible ASCII, spaces and tabs.
    #[test]
    fn checks_header_values() {
        assert!(is_header_value("max-age=63072000; includeSubDomains"));
        assert!(is_header_value("a\tb"));
        assert!(is_header_value(""));
        assert!(!is_header_value("a\r\nb"));
        assert!(!is_header_value("é"));
        assert_eq!("a b".parse::<HeaderValue>().unwrap().as_str(), "a b");
        assert_eq!(
            "a\nb".parse::<HeaderValue>(),
            Err(InvalidHeaderValue("a\nb".to_owned()))
        );
    }
}
