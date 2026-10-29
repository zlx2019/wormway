//! What a route does with the requests it takes: forward them to an upstream, redirect them or
//! answer them, and the changes made to requests and responses on the way.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{HeaderName, HeaderValue, Name};

/// What a route does with a request, from [`super::Route::action`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// Forward it to this upstream.
    Upstream(&'a Name),
    /// Send the client elsewhere.
    Redirect(&'a Redirect),
    /// Answer it with a fixed response.
    Respond(&'a Respond),
}

/// An answer that sends the client elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// Where to: a URL or a path. `{host}` stands for the host name of the request, without the
    /// port, and `{uri}` for its path and query as sent, as in `"https://{host}{uri}"`.
    pub to: String,
    /// Status code: 301 or 308 for a permanent move, 302, 303 or 307 for a temporary one; 307
    /// and 308 keep the method and the body. Default: 302.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

impl Redirect {
    /// Default of `status`.
    pub const DEFAULT_STATUS: u16 = 302;
    /// Status codes a redirect can have.
    pub const STATUSES: [u16; 5] = [301, 302, 303, 307, 308];

    /// Returns the status code in effect.
    pub fn status(&self) -> u16 {
        self.status.unwrap_or(Self::DEFAULT_STATUS)
    }

    /// Splits `to` into text and placeholders, or tells what is wrong with it.
    pub fn parts(&self) -> Result<Vec<RedirectPart<'_>>, String> {
        let mut parts = Vec::new();
        let mut rest = self.to.as_str();
        while let Some(start) = rest.find(['{', '}']) {
            if rest[start..].starts_with('}') {
                return Err("has a \"}\" without \"{\"".to_owned());
            }
            if start > 0 {
                parts.push(RedirectPart::Text(&rest[..start]));
            }
            let after = &rest[start + 1..];
            let end = after
                .find('}')
                .ok_or_else(|| "has a \"{\" without \"}\"".to_owned())?;
            parts.push(match &after[..end] {
                "host" => RedirectPart::Host,
                "uri" => RedirectPart::Uri,
                other => {
                    return Err(format!(
                        "has an unknown placeholder {{{other}}}, expected {{host}} or {{uri}}"
                    ));
                }
            });
            rest = &after[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(RedirectPart::Text(rest));
        }
        Ok(parts)
    }
}

/// A piece of the target of a redirect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectPart<'a> {
    /// Text, written as it is.
    Text(&'a str),
    /// The host name of the request, without the port.
    Host,
    /// The path and the query of the request, as sent.
    Uri,
}

/// A fixed answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Respond {
    /// Status code, from 200 to 599.
    pub status: u16,
    /// Body, empty by default. A body is sent as `text/plain; charset=utf-8` unless
    /// `response_headers` set another `Content-Type`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
}

/// Changes to the path of the requests sent to the upstream. They apply to the normalized path,
/// which is then encoded again; the query stays as it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// Removed from the start of the path when the path starts with it, such as `/v1`: `/v1/users`
    /// becomes `/users`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strip_prefix: Option<String>,
    /// Added in front of the path, after `strip_prefix`, such as `/api`: `/users` becomes
    /// `/api/users`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_prefix: Option<String>,
}

/// Changes to the headers of a message, made in this order: `remove`, `set`, `add`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HeaderRules {
    /// Headers to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<HeaderName>,
    /// Headers to set, replacing the values they have.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<HeaderName, HeaderValue>,
    /// Values to add after the ones the headers have.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub add: BTreeMap<HeaderName, HeaderValue>,
}

impl HeaderRules {
    /// Whether there is no change.
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.set.is_empty() && self.add.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A redirect to `to`.
    fn redirect(to: &str) -> Redirect {
        Redirect {
            to: to.to_owned(),
            status: None,
        }
    }

    /// Targets split into text and the two placeholders.
    #[test]
    fn splits_redirect_targets() {
        use RedirectPart::{Host, Text, Uri};
        assert_eq!(
            redirect("https://{host}{uri}").parts().unwrap(),
            [Text("https://"), Host, Uri]
        );
        assert_eq!(
            redirect("https://{host}:8443/new{uri}").parts().unwrap(),
            [Text("https://"), Host, Text(":8443/new"), Uri]
        );
        assert_eq!(redirect("/").parts().unwrap(), [Text("/")]);
        assert_eq!(redirect("").parts().unwrap(), []);
        assert_eq!(redirect("https://example.com").status(), 302);
    }

    /// Unknown placeholders and unbalanced braces are reported.
    #[test]
    fn rejects_malformed_targets() {
        assert_eq!(
            redirect("https://{hots}/").parts().unwrap_err(),
            "has an unknown placeholder {hots}, expected {host} or {uri}"
        );
        assert!(redirect("https://{host").parts().is_err());
        assert!(redirect("https://host}/").parts().is_err());
        assert!(redirect("{}").parts().is_err());
    }
}
