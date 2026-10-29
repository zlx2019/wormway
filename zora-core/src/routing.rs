//! Route matching: finds the route of an HTTP request by its host and path.
//!
//! When several routes match, the most specific one wins: an exact host before a wildcard host
//! before any host, then the longest path prefix, then the route that came first.

use std::cmp::Reverse;

use crate::config::{HostPattern, RouteMatch};

/// Finds the route of a request. It is built once per configuration and then shared by every
/// request.
#[derive(Debug)]
pub struct Router<T> {
    /// One entry per host and path of every route, the most specific first.
    entries: Vec<Entry>,
    /// The routes that the entries point to.
    routes: Vec<T>,
}

/// One host and one path prefix of a route.
#[derive(Debug)]
struct Entry {
    /// Host condition.
    host: HostMatch,
    /// Path prefix; empty for any path.
    prefix: Box<str>,
    /// Index of the route in `Router::routes`.
    route: usize,
}

/// The host condition of an entry.
#[derive(Clone, Debug)]
enum HostMatch {
    /// This host name, in lowercase.
    Exact(Box<str>),
    /// One label in front of this suffix, which starts with a dot, such as `.example.com`.
    Wildcard(Box<str>),
    /// Any host, and requests without one.
    Any,
}

impl HostMatch {
    /// Precedence of the condition: lower values are more specific.
    fn rank(&self) -> u8 {
        match self {
            Self::Exact(_) => 0,
            Self::Wildcard(_) => 1,
            Self::Any => 2,
        }
    }

    /// Whether `host`, in any case, meets the condition.
    fn matches(&self, host: Option<&str>) -> bool {
        match (self, host) {
            (Self::Any, _) => true,
            (Self::Exact(name), Some(host)) => host.eq_ignore_ascii_case(name),
            (Self::Wildcard(suffix), Some(host)) => {
                // Compare bytes: the host may contain characters that are not ASCII.
                let Some(split) = host.len().checked_sub(suffix.len()) else {
                    return false;
                };
                let (label, rest) = host.as_bytes().split_at(split);
                !label.is_empty()
                    && !label.contains(&b'.')
                    && rest.eq_ignore_ascii_case(suffix.as_bytes())
            }
            (_, None) => false,
        }
    }
}

impl From<&HostPattern> for HostMatch {
    /// Splits off the wildcard of a pattern.
    fn from(pattern: &HostPattern) -> Self {
        match pattern.wildcard_suffix() {
            Some(suffix) => Self::Wildcard(format!(".{suffix}").into()),
            None => Self::Exact(pattern.as_str().into()),
        }
    }
}

impl<T> Router<T> {
    /// Builds a router from routes and their conditions. When two routes are equally specific,
    /// the one that comes first wins, so pass them in name order.
    pub fn new<'a>(routes: impl IntoIterator<Item = (&'a RouteMatch, T)>) -> Self {
        let mut entries = Vec::new();
        let mut values = Vec::new();
        for (index, (conditions, route)) in routes.into_iter().enumerate() {
            let hosts: Vec<HostMatch> = if conditions.hosts.is_empty() {
                vec![HostMatch::Any]
            } else {
                conditions.hosts.iter().map(HostMatch::from).collect()
            };
            let paths: Vec<&str> = if conditions.paths.is_empty() {
                vec![""]
            } else {
                conditions.paths.iter().map(String::as_str).collect()
            };
            for host in &hosts {
                for path in &paths {
                    entries.push(Entry {
                        host: host.clone(),
                        prefix: (*path).into(),
                        route: index,
                    });
                }
            }
            values.push(route);
        }
        // A stable sort, so that equally specific entries keep the order of their routes.
        entries.sort_by_key(|entry| (entry.host.rank(), Reverse(entry.prefix.len())));
        Self {
            entries,
            routes: values,
        }
    }

    /// Returns the route of a request. `host` is the host name of the request without the port,
    /// in any case, or `None` if the request names no host.
    pub fn find(&self, host: Option<&str>, path: &str) -> Option<&T> {
        self.entries
            .iter()
            .find(|entry| path.starts_with(&*entry.prefix) && entry.host.matches(host))
            .and_then(|entry| self.routes.get(entry.route))
    }
}

/// Returns the host name of an HTTP authority, such as the value of a `Host` header: without
/// the port and without a trailing dot. IPv6 addresses keep their brackets.
pub fn host_name(authority: &str) -> &str {
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map_or(authority, |end| &authority[..=end])
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _port)| host)
    };
    host.strip_suffix('.').unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conditions from host patterns and path prefixes.
    fn conditions(hosts: &[&str], paths: &[&str]) -> RouteMatch {
        RouteMatch {
            hosts: hosts.iter().map(|host| host.parse().unwrap()).collect(),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    /// A router over named routes, given in name order.
    fn router(routes: &[(&'static str, RouteMatch)]) -> Router<&'static str> {
        Router::new(routes.iter().map(|(name, conditions)| (conditions, *name)))
    }

    /// An exact host beats a wildcard host, which beats any host, whatever the paths.
    #[test]
    fn prefers_specific_hosts() {
        let router = router(&[
            ("any", conditions(&[], &["/api/v1/"])),
            ("exact", conditions(&["api.example.com"], &["/"])),
            ("wildcard", conditions(&["*.example.com"], &["/api/"])),
        ]);
        assert_eq!(
            router.find(Some("api.example.com"), "/api/v1/x"),
            Some(&"exact")
        );
        assert_eq!(
            router.find(Some("www.example.com"), "/api/v1/x"),
            Some(&"wildcard")
        );
        assert_eq!(router.find(Some("www.example.com"), "/"), None);
        assert_eq!(router.find(Some("example.org"), "/api/v1/x"), Some(&"any"));
    }

    /// Within one kind of host, the longest prefix wins; equal ones go to the first route.
    #[test]
    fn prefers_longer_prefixes_then_the_first_route() {
        let router = router(&[
            ("a-root", conditions(&[], &[])),
            ("b-api", conditions(&[], &["/api"])),
            ("c-api-v1", conditions(&[], &["/api/v1/"])),
            ("d-api-again", conditions(&[], &["/api"])),
        ]);
        assert_eq!(router.find(None, "/api/v1/users"), Some(&"c-api-v1"));
        assert_eq!(router.find(None, "/api/v2"), Some(&"b-api"));
        assert_eq!(router.find(None, "/apis"), Some(&"b-api"));
        assert_eq!(router.find(None, "/"), Some(&"a-root"));
    }

    /// Hosts compare without case, a wildcard covers exactly one label, and requests without a
    /// host only match routes without hosts.
    #[test]
    fn matches_hosts() {
        let router = router(&[
            ("exact", conditions(&["example.com"], &[])),
            ("wildcard", conditions(&["*.example.com"], &[])),
        ]);
        assert_eq!(router.find(Some("EXAMPLE.com"), "/"), Some(&"exact"));
        assert_eq!(router.find(Some("Www.Example.Com"), "/"), Some(&"wildcard"));
        assert_eq!(router.find(Some("a.b.example.com"), "/"), None);
        assert_eq!(router.find(Some(".example.com"), "/"), None);
        assert_eq!(router.find(Some("badexample.com"), "/"), None);
        assert_eq!(router.find(Some("é.example.com"), "/"), Some(&"wildcard"));
        assert_eq!(router.find(Some("ééé"), "/"), None);
        assert_eq!(router.find(None, "/"), None);
    }

    /// Every host and path of a route counts, and an empty router finds nothing.
    #[test]
    fn combines_hosts_and_paths() {
        let router = router(&[(
            "site",
            conditions(&["a.example.com", "b.example.com"], &["/x/", "/y/"]),
        )]);
        assert_eq!(router.find(Some("b.example.com"), "/y/1"), Some(&"site"));
        assert_eq!(router.find(Some("a.example.com"), "/x/1"), Some(&"site"));
        assert_eq!(router.find(Some("a.example.com"), "/z/1"), None);
        assert_eq!(Router::<()>::new([]).find(Some("a.example.com"), "/"), None);
    }

    /// Ports and trailing dots are removed; IPv6 addresses keep their brackets.
    #[test]
    fn extracts_host_names() {
        assert_eq!(host_name("example.com"), "example.com");
        assert_eq!(host_name("example.com:8080"), "example.com");
        assert_eq!(host_name("example.com."), "example.com");
        assert_eq!(host_name("example.com.:443"), "example.com");
        assert_eq!(host_name("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(host_name("[::1]:8080"), "[::1]");
        assert_eq!(host_name("[::1]"), "[::1]");
    }
}
