//! Routes ready to serve requests: what each does with a request, and what it changes on the
//! way.

use std::collections::BTreeMap;
use std::sync::Arc;

use wormway_core::config::{
    Action, Issue, Name, Redirect, RedirectPart, Respond, Rewrite, Route, RouteTimeouts,
};

use crate::headers::HeaderEdits;
use crate::upstream::CompiledUpstream;

/// A route ready to serve requests.
pub(crate) struct CompiledRoute {
    /// What the route does with a request.
    pub(crate) handler: Handler,
    /// Changes to the path of the requests sent to the upstream.
    pub(crate) rewrite: Option<Rewrite>,
    /// Changes to the headers of the requests sent to the upstream.
    pub(crate) request_headers: HeaderEdits,
    /// Changes to the headers of the responses.
    pub(crate) response_headers: HeaderEdits,
    /// Whether responses are compressed.
    pub(crate) compress: bool,
    /// Time limits of the requests to the upstream, in place of those of the upstream.
    pub(crate) timeouts: RouteTimeouts,
}

/// What a route does with a request.
pub(crate) enum Handler {
    /// Forward it to this upstream.
    Upstream(Arc<CompiledUpstream>),
    /// Answer with a redirect.
    Redirect(RedirectTarget),
    /// Answer with a fixed response.
    Respond(FixedResponse),
}

impl CompiledRoute {
    /// Compiles route `name`, with its upstream from `upstreams`. The route passed validation,
    /// so this fails only if the validation rules miss a case.
    pub(crate) fn new(
        name: &Name,
        route: &Route,
        upstreams: &BTreeMap<Name, Arc<CompiledUpstream>>,
    ) -> Result<Self, Issue> {
        let at = |field: &str| format!("routes.{name}{field}");
        let handler = match route.action() {
            Some(Action::Upstream(upstream)) => match upstreams.get(upstream) {
                Some(runtime) => Handler::Upstream(runtime.clone()),
                None => {
                    let problem = format!("unknown upstream \"{upstream}\"");
                    return Err(Issue::new(at(".upstream"), problem));
                }
            },
            Some(Action::Redirect(redirect)) => Handler::Redirect(
                RedirectTarget::new(redirect)
                    .map_err(|problem| Issue::new(at(".redirect.to"), problem))?,
            ),
            Some(Action::Respond(respond)) => Handler::Respond(FixedResponse::new(respond)),
            None => {
                let problem = "set exactly one of upstream, redirect and respond";
                return Err(Issue::new(at(""), problem));
            }
        };
        let request_headers = HeaderEdits::new(&route.request_headers)
            .map_err(|problem| Issue::new(at(".request_headers"), problem))?;
        let response_headers = HeaderEdits::new(&route.response_headers)
            .map_err(|problem| Issue::new(at(".response_headers"), problem))?;
        Ok(Self {
            handler,
            rewrite: route.rewrite.clone(),
            request_headers,
            response_headers,
            compress: route.compress(),
            timeouts: route.timeouts,
        })
    }

    /// Returns the upstream of a route that forwards requests.
    pub(crate) fn upstream(&self) -> Option<&Arc<CompiledUpstream>> {
        match &self.handler {
            Handler::Upstream(upstream) => Some(upstream),
            Handler::Redirect(_) | Handler::Respond(_) => None,
        }
    }
}

/// Where a redirect sends the client, and with which status.
pub(crate) struct RedirectTarget {
    /// The target, in pieces.
    parts: Vec<Part>,
    /// The status code.
    pub(crate) status: u16,
}

/// A piece of the target of a redirect.
enum Part {
    /// Text, written as it is.
    Text(Box<str>),
    /// The host name of the request, without the port.
    Host,
    /// The path and the query of the request, as sent.
    Uri,
}

impl RedirectTarget {
    /// Splits the target of `redirect` into its pieces.
    fn new(redirect: &Redirect) -> Result<Self, String> {
        let parts = redirect
            .parts()?
            .into_iter()
            .map(|part| match part {
                RedirectPart::Text(text) => Part::Text(text.into()),
                RedirectPart::Host => Part::Host,
                RedirectPart::Uri => Part::Uri,
            })
            .collect();
        Ok(Self {
            parts,
            status: redirect.status(),
        })
    }

    /// Returns the location for a request to `host` with request target `uri`, or `None` if
    /// the target needs a host name and the request has no usable one.
    pub(crate) fn location(&self, host: Option<&str>, uri: &[u8]) -> Option<Vec<u8>> {
        let mut location = Vec::new();
        for part in &self.parts {
            match part {
                Part::Text(text) => location.extend_from_slice(text.as_bytes()),
                Part::Host => {
                    // The Host header comes from the client: only a host name may go into the
                    // location, not a path, a query or another URL.
                    let host = host.filter(|host| is_host_name(host))?;
                    location.extend_from_slice(host.as_bytes());
                }
                Part::Uri => location.extend_from_slice(uri),
            }
        }
        Some(location)
    }
}

/// Whether `host` can stand in a URL as a host: letters, digits, `-`, `.` and `_`, or an IPv6
/// address in brackets.
fn is_host_name(host: &str) -> bool {
    let ipv6 = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(|address| address.parse::<std::net::Ipv6Addr>().is_ok());
    ipv6 || (!host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')))
}

/// A fixed answer.
pub(crate) struct FixedResponse {
    /// The status code.
    pub(crate) status: u16,
    /// The body.
    pub(crate) body: Box<[u8]>,
}

impl FixedResponse {
    /// Takes the status and the body of `respond`.
    fn new(respond: &Respond) -> Self {
        Self {
            status: respond.status,
            body: respond.body.as_bytes().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redirect to `to`.
    fn target(to: &str) -> RedirectTarget {
        let redirect = Redirect {
            to: to.to_owned(),
            status: Some(301),
        };
        RedirectTarget::new(&redirect).unwrap()
    }

    /// The location as text.
    fn location(target: &RedirectTarget, host: Option<&str>, uri: &str) -> Option<String> {
        let location = target.location(host, uri.as_bytes())?;
        Some(String::from_utf8(location).unwrap())
    }

    /// Placeholders take the host name and the request target; the status stays.
    #[test]
    fn builds_locations() {
        let https = target("https://{host}{uri}");
        assert_eq!(https.status, 301);
        assert_eq!(
            location(&https, Some("example.com"), "/a?b=1").as_deref(),
            Some("https://example.com/a?b=1")
        );
        assert_eq!(
            location(&https, Some("[::1]"), "/").as_deref(),
            Some("https://[::1]/")
        );
        let fixed = target("https://example.org/new");
        assert_eq!(
            location(&fixed, None, "/old").as_deref(),
            Some("https://example.org/new")
        );
    }

    /// Without a host name, or with one that is not a plain host name, there is no location.
    #[test]
    fn needs_plain_host_names() {
        let https = target("https://{host}{uri}");
        for host in [
            None,
            Some(""),
            Some("evil.com/x"),
            Some("a b"),
            Some("[nope]"),
        ] {
            assert_eq!(location(&https, host, "/"), None, "{host:?}");
        }
    }
}
