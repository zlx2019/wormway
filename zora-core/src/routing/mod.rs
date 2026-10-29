//! Route matching: finds the route of an HTTP request by its host, path, method and headers.
//!
//! When several routes match, the rules of [`Route`] pick one. Paths are compared after
//! [`normalize_path`]. A router is built once per configuration and then shared by every
//! request: hosts are looked up in hash tables, exact paths too, and prefixes by binary search,
//! so that the time of a lookup hardly grows with the number of routes. Regular expressions are
//! tried one by one, best first, until one matches.

mod path;
mod table;

use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::HashMap;

pub use path::normalize_path;
use table::{HostKind, PathKind, PathTable, PathTableBuilder, Rank};

use crate::config::{HeaderCondition, Route};

/// The headers of a request, as the router reads them.
pub trait RequestHeaders {
    /// Whether the request has header `name`, given in lowercase.
    fn contains(&self, name: &str) -> bool;
    /// Whether one of the values of header `name`, given in lowercase, is `value`.
    fn has_value(&self, name: &str, value: &[u8]) -> bool;
}

/// What the router reads from a request.
pub struct Request<'a> {
    /// Host name without the port, in any case, or `None` if the request names no host.
    pub host: Option<&'a str>,
    /// The path, after [`normalize_path`].
    pub path: &'a [u8],
    /// The method, such as `GET`.
    pub method: &'a str,
    /// The headers.
    pub headers: &'a dyn RequestHeaders,
}

/// Finds the route of a request.
pub struct Router<T> {
    /// The routes, in the order they were given.
    routes: Vec<Entry<T>>,
    /// Paths of the routes for each exact host name, in lowercase.
    exact_hosts: HashMap<Box<str>, PathTable>,
    /// Paths of the routes for each wildcard host, by the name after the wildcard label, such
    /// as `example.com` for `*.example.com`.
    wildcard_hosts: HashMap<Box<str>, PathTable>,
    /// Paths of the routes for any host.
    any_host: PathTable,
}

/// A route and the conditions that the path tables do not check.
struct Entry<T> {
    /// What the caller attached to the route.
    value: T,
    /// Methods; empty for any method.
    methods: Box<[Box<str>]>,
    /// Header conditions, with the names in lowercase.
    headers: Box<[(Box<str>, HeaderCondition)]>,
}

impl<T> Entry<T> {
    /// Whether `request` meets the method and header conditions.
    fn accepts(&self, request: &Request<'_>) -> bool {
        (self.methods.is_empty()
            || self
                .methods
                .iter()
                .any(|method| **method == *request.method))
            && self
                .headers
                .iter()
                .all(|(name, condition)| match condition {
                    HeaderCondition::Equals(value) => {
                        request.headers.has_value(name, value.as_bytes())
                    }
                    HeaderCondition::Present(present) => request.headers.contains(name) == *present,
                })
    }
}

impl<T> Router<T> {
    /// Builds a router from routes and the values to return for them. When two routes are
    /// equal by every rule, the one that comes first wins, so pass them in name order.
    pub fn new<'a>(routes: impl IntoIterator<Item = (&'a Route, T)>) -> Self {
        let mut exact_hosts: HashMap<Box<str>, PathTableBuilder> = HashMap::new();
        let mut wildcard_hosts: HashMap<Box<str>, PathTableBuilder> = HashMap::new();
        let mut any_host = PathTableBuilder::default();
        let mut entries = Vec::new();
        for (index, (route, value)) in routes.into_iter().enumerate() {
            let conditions = &route.r#match;
            let rank = Rank {
                priority: Reverse(route.priority),
                host: HostKind::Any,
                path: (PathKind::Prefix, Reverse(0)),
                any_method: conditions.methods.is_empty(),
                headers: Reverse(conditions.headers.len()),
                route: index,
            };
            let add_paths = |table: &mut PathTableBuilder, host| {
                let rank = Rank { host, ..rank };
                if conditions.paths.is_empty() {
                    table.add(None, rank);
                }
                for path in &conditions.paths {
                    table.add(Some(path), rank);
                }
            };
            if conditions.hosts.is_empty() {
                add_paths(&mut any_host, HostKind::Any);
            }
            for host in &conditions.hosts {
                match host.wildcard_suffix() {
                    Some(suffix) => add_paths(
                        wildcard_hosts.entry(suffix.into()).or_default(),
                        HostKind::Wildcard,
                    ),
                    None => add_paths(
                        exact_hosts.entry(host.as_str().into()).or_default(),
                        HostKind::Exact,
                    ),
                }
            }
            entries.push(Entry {
                value,
                methods: conditions
                    .methods
                    .iter()
                    .map(|m| m.as_str().into())
                    .collect(),
                headers: conditions
                    .headers
                    .iter()
                    .map(|(name, condition)| {
                        (name.as_str().to_ascii_lowercase().into(), condition.clone())
                    })
                    .collect(),
            });
        }
        let build = |tables: HashMap<Box<str>, PathTableBuilder>| {
            tables
                .into_iter()
                .map(|(host, table)| (host, table.build()))
                .collect()
        };
        Self {
            routes: entries,
            exact_hosts: build(exact_hosts),
            wildcard_hosts: build(wildcard_hosts),
            any_host: any_host.build(),
        }
    }

    /// Returns the value of the route of `request`, or `None` if no route matches.
    pub fn find(&self, request: &Request<'_>) -> Option<&T> {
        let accepts = |route: usize| self.routes[route].accepts(request);
        let mut best = None;
        if let Some(host) = request.host {
            let host = lowercase(host);
            if let Some(table) = self.exact_hosts.get(&*host) {
                table.find(request.path, &mut best, &accepts);
            }
            if let Some((label, parent)) = host.split_once('.')
                && !label.is_empty()
                && let Some(table) = self.wildcard_hosts.get(parent)
            {
                table.find(request.path, &mut best, &accepts);
            }
        }
        self.any_host.find(request.path, &mut best, &accepts);
        best.map(|rank| &self.routes[rank.route].value)
    }
}

/// Returns `host` in lowercase, copying it only if it has uppercase letters.
fn lowercase(host: &str) -> Cow<'_, str> {
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
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
    use crate::config::Config;

    /// Headers as name and value pairs, with names compared without case.
    struct Headers<'a>(&'a [(&'a str, &'a str)]);

    impl RequestHeaders for Headers<'_> {
        /// Whether a pair has the name.
        fn contains(&self, name: &str) -> bool {
            self.0.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
        }

        /// Whether a pair has the name and the value.
        fn has_value(&self, name: &str, value: &[u8]) -> bool {
            self.0
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case(name) && v.as_bytes() == value)
        }
    }

    /// A router over the routes of a TOML text with `[routes.<name>]` tables, whose values are
    /// the route names. Every route goes to upstream "app".
    fn router(routes: &str) -> Router<String> {
        let text = format!("version = 1\n[upstreams.app]\ntargets = [\"127.0.0.1:1\"]\n{routes}");
        let config = Config::from_toml(&text).unwrap();
        Router::new(
            config
                .routes
                .iter()
                .map(|(name, route)| (route, name.to_string())),
        )
    }

    /// The route of a GET request without headers.
    fn get<'a>(router: &'a Router<String>, host: Option<&str>, path: &str) -> Option<&'a str> {
        find(router, host, "GET", path, &[])
    }

    /// The route of a request.
    fn find<'a>(
        router: &'a Router<String>,
        host: Option<&str>,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Option<&'a str> {
        let request = Request {
            host,
            path: &normalize_path(path.as_bytes()),
            method,
            headers: &Headers(headers),
        };
        router.find(&request).map(String::as_str)
    }

    /// An exact host beats a wildcard host, which beats any host, whatever the paths.
    #[test]
    fn prefers_specific_hosts() {
        let router = router(
            r#"
            [routes.any]
            match = { paths = ["/api/v1/"] }
            upstream = "app"
            [routes.exact]
            match = { hosts = ["api.example.com"], paths = ["/"] }
            upstream = "app"
            [routes.wildcard]
            match = { hosts = ["*.example.com"], paths = ["/api/"] }
            upstream = "app"
            "#,
        );
        assert_eq!(
            get(&router, Some("api.example.com"), "/api/v1/x"),
            Some("exact")
        );
        assert_eq!(
            get(&router, Some("www.example.com"), "/api/v1/x"),
            Some("wildcard")
        );
        assert_eq!(get(&router, Some("www.example.com"), "/"), None);
        assert_eq!(get(&router, Some("example.org"), "/api/v1/x"), Some("any"));
    }

    /// Exact paths beat regular expressions, which beat prefixes, longest first, which beat
    /// any path; equal ones go to the first route.
    #[test]
    fn prefers_specific_paths() {
        let router = router(
            r#"
            [routes.a-any]
            upstream = "app"
            [routes.b-api]
            match = { paths = ["/api"] }
            upstream = "app"
            [routes.c-api-v1]
            match = { paths = ["/api/v1/"] }
            upstream = "app"
            [routes.d-api-again]
            match = { paths = ["/api"] }
            upstream = "app"
            [routes.e-json]
            match = { paths = [{ regex = "\\.json$" }] }
            upstream = "app"
            [routes.f-users]
            match = { paths = [{ exact = "/api/v1/users.json" }] }
            upstream = "app"
            [routes.g-root]
            match = { paths = ["/"] }
            upstream = "app"
            "#,
        );
        assert_eq!(get(&router, None, "/api/v1/users"), Some("c-api-v1"));
        assert_eq!(get(&router, None, "/api/v2"), Some("b-api"));
        assert_eq!(get(&router, None, "/apis"), Some("b-api"));
        assert_eq!(get(&router, None, "/"), Some("g-root"));
        assert_eq!(get(&router, None, "/x"), Some("g-root"));
        assert_eq!(get(&router, None, "*"), Some("a-any"));
        assert_eq!(get(&router, None, "/api/v1/orders.json"), Some("e-json"));
        assert_eq!(get(&router, None, "/api/v1/users.json"), Some("f-users"));
        assert_eq!(get(&router, None, "/api/v1/users.json/x"), Some("c-api-v1"));
    }

    /// Priorities come before every other rule.
    #[test]
    fn prefers_higher_priorities() {
        let router = router(
            r#"
            [routes.exact]
            match = { hosts = ["example.com"], paths = [{ exact = "/" }] }
            upstream = "app"
            [routes.low]
            priority = -1
            match = { hosts = ["example.com"] }
            upstream = "app"
            [routes.urgent]
            priority = 10
            match = { paths = ["/"] }
            upstream = "app"
            "#,
        );
        assert_eq!(get(&router, Some("example.com"), "/"), Some("urgent"));
        assert_eq!(get(&router, Some("example.com"), "*"), Some("low"));
    }

    /// Methods and headers are conditions; routes with methods, then routes with more header
    /// conditions, win among equally specific ones.
    #[test]
    fn checks_methods_and_headers() {
        let router = router(
            r#"
            [routes.a-read]
            match = { paths = ["/api/"] }
            upstream = "app"
            [routes.b-write]
            match = { paths = ["/api/"], methods = ["post", "PUT"] }
            upstream = "app"
            [routes.c-canary]
            match = { paths = ["/api/"], headers = { "X-Canary" = "1" } }
            upstream = "app"
            [routes.d-canary-signed]
            match = { paths = ["/api/"], headers = { "X-Canary" = "1", "authorization" = true } }
            upstream = "app"
            [routes.e-anonymous]
            match = { paths = ["/public/"], headers = { "Authorization" = false } }
            upstream = "app"
            "#,
        );
        let api = |method, headers: &[(&str, &str)]| find(&router, None, method, "/api/x", headers);
        assert_eq!(api("GET", &[]), Some("a-read"));
        assert_eq!(api("POST", &[]), Some("b-write"));
        assert_eq!(api("PUT", &[("X-Canary", "1")]), Some("b-write"));
        assert_eq!(api("GET", &[("x-canary", "1")]), Some("c-canary"));
        assert_eq!(api("GET", &[("X-Canary", "2")]), Some("a-read"));
        assert_eq!(
            api(
                "GET",
                &[("X-Canary", "0"), ("X-Canary", "1"), ("Authorization", "")]
            ),
            Some("d-canary-signed")
        );
        let public = |headers: &[(&str, &str)]| find(&router, None, "GET", "/public/", headers);
        assert_eq!(public(&[]), Some("e-anonymous"));
        assert_eq!(public(&[("Authorization", "Basic x")]), None);
    }

    /// Hosts compare without case, a wildcard covers exactly one label, and requests without a
    /// host only match routes without hosts.
    #[test]
    fn matches_hosts() {
        let router = router(
            r#"
            [routes.exact]
            match = { hosts = ["example.com"] }
            upstream = "app"
            [routes.wildcard]
            match = { hosts = ["*.example.com"] }
            upstream = "app"
            "#,
        );
        assert_eq!(get(&router, Some("EXAMPLE.com"), "/"), Some("exact"));
        assert_eq!(get(&router, Some("Www.Example.Com"), "/"), Some("wildcard"));
        assert_eq!(get(&router, Some("a.b.example.com"), "/"), None);
        assert_eq!(get(&router, Some(".example.com"), "/"), None);
        assert_eq!(get(&router, Some("badexample.com"), "/"), None);
        assert_eq!(get(&router, Some("é.example.com"), "/"), Some("wildcard"));
        assert_eq!(get(&router, Some("ééé"), "/"), None);
        assert_eq!(get(&router, None, "/"), None);
    }

    /// Every host and path of a route counts, and an empty router finds nothing.
    #[test]
    fn combines_hosts_and_paths() {
        let router = router(
            r#"
            [routes.site]
            match = { hosts = ["a.example.com", "b.example.com"], paths = ["/x/", "/y/"] }
            upstream = "app"
            "#,
        );
        assert_eq!(get(&router, Some("b.example.com"), "/y/1"), Some("site"));
        assert_eq!(get(&router, Some("a.example.com"), "/x/1"), Some("site"));
        assert_eq!(get(&router, Some("a.example.com"), "/z/1"), None);
        assert_eq!(get(&Router::new([]), Some("a.example.com"), "/"), None);
    }

    /// Paths match after normalization, so dot segments and escapes cannot avoid a route.
    #[test]
    fn matches_normalized_paths() {
        let router = router(
            r#"
            [routes.admin]
            match = { paths = ["/admin/"] }
            upstream = "app"
            [routes.site]
            upstream = "app"
            [routes.unicode]
            match = { paths = [{ regex = "^/été$" }] }
            upstream = "app"
            "#,
        );
        for path in [
            "/public/../admin/x",
            "/admin%2Fx",
            "//admin//x",
            "/%61dmin/x",
        ] {
            assert_eq!(get(&router, None, path), Some("admin"), "{path:?}");
        }
        assert_eq!(get(&router, None, "/%C3%A9t%C3%A9"), Some("unicode"));
        assert_eq!(get(&router, None, "/%E9t%E9"), Some("site"));
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
