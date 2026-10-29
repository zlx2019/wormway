//! Benchmarks of route matching: lookups among 1, 100 and 10,000 routes, and path
//! normalization.
//!
//! Every set of routes also holds a route for any request and three regular expressions for any
//! host, as most configurations have. Run with `cargo bench -p zora-core`.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use zora_core::config::{PathPattern, Route, RouteMatch};
use zora_core::routing::{Request, RequestHeaders, Router, normalize_path};

/// Numbers of routes to look up among.
const SIZES: [usize; 3] = [1, 100, 10_000];

/// A request without headers.
struct NoHeaders;

impl RequestHeaders for NoHeaders {
    /// No header is present.
    fn contains(&self, _name: &str) -> bool {
        false
    }

    /// No header has a value.
    fn has_value(&self, _name: &str, _value: &[u8]) -> bool {
        false
    }
}

/// A route for `hosts`, or any host if empty, and `paths`, or any path if empty.
fn route(hosts: &[String], paths: Vec<PathPattern>) -> Route {
    Route {
        listeners: Vec::new(),
        priority: 0,
        r#match: RouteMatch {
            hosts: hosts
                .iter()
                .map(|host| host.parse().expect("valid host"))
                .collect(),
            paths,
            methods: Vec::new(),
            headers: BTreeMap::new(),
        },
        upstream: "app".parse().expect("valid name"),
    }
}

/// A prefix condition.
fn prefix(path: &str) -> PathPattern {
    PathPattern::Prefix(path.to_owned())
}

/// The routes that every set holds: one for any request and three regular expressions.
fn common_routes() -> Vec<Route> {
    let regexes = [r"^/static/.+\.(css|js)$", r"\.php$", r"^/v[0-9]+/"];
    let mut routes: Vec<Route> = regexes
        .iter()
        .map(|regex| {
            let regex = PathPattern::Regex(regex.parse().expect("valid regex"));
            route(&[], vec![regex])
        })
        .collect();
    routes.push(route(&[], Vec::new()));
    routes
}

/// `count` routes, each for its own host with two prefixes, as for many sites.
fn host_routes(count: usize) -> Vec<Route> {
    let mut routes = common_routes();
    routes.extend((0..count).map(|i| {
        route(
            &[format!("site{i}.example.com")],
            vec![prefix("/"), prefix("/api/")],
        )
    }));
    routes
}

/// `count` routes for one host, each with its own prefix, as for many services behind one API.
fn path_routes(count: usize) -> Vec<Route> {
    let mut routes = common_routes();
    let host = ["api.example.com".to_owned()];
    routes.extend((0..count).map(|i| route(&host, vec![prefix(&format!("/svc{i}/v1/"))])));
    routes
}

/// Builds a router over `routes`.
fn router(routes: &[Route]) -> Router<usize> {
    Router::new(routes.iter().zip(0..))
}

/// Measures the lookup of `host` and `path` in `group` for every size of `routes`.
fn lookups(
    c: &mut Criterion,
    group: &str,
    routes: fn(usize) -> Vec<Route>,
    request: fn(usize) -> (String, String),
) {
    let mut group = c.benchmark_group(group);
    for size in SIZES {
        let routes = routes(size);
        let router = router(&routes);
        let (host, path) = request(size);
        let request = Request {
            host: Some(&host),
            path: path.as_bytes(),
            method: "GET",
            headers: &NoHeaders,
        };
        assert!(
            router.find(&request).is_some(),
            "{host}{path} finds no route"
        );
        group.bench_with_input(BenchmarkId::from_parameter(size), &request, |b, request| {
            b.iter(|| router.find(black_box(request)));
        });
    }
    group.finish();
}

/// Route lookups for each shape of configuration.
fn route_lookups(c: &mut Criterion) {
    lookups(c, "route/hosts", host_routes, |size| {
        (
            format!("site{}.example.com", size / 2),
            "/api/users/42".to_owned(),
        )
    });
    lookups(c, "route/paths", path_routes, |size| {
        (
            "api.example.com".to_owned(),
            format!("/svc{}/v1/items/7", size / 2),
        )
    });
    // A host that no route names, so that the regular expressions run before the route for any
    // request wins.
    lookups(c, "route/fallback", host_routes, |_| {
        ("www.example.org".to_owned(), "/about/team".to_owned())
    });
}

/// Normalization of a path in normal form and of one that needs decoding and resolving.
fn normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize");
    for (name, path) in [
        ("normal", "/api/v1/users/42/orders"),
        ("encoded", "/api/v1/../v2//users/%34%32/orders"),
    ] {
        group.bench_with_input(name, path.as_bytes(), |b, path| {
            b.iter(|| normalize_path(black_box(path)));
        });
    }
    group.finish();
}

criterion_group!(benches, route_lookups, normalization);
criterion_main!(benches);
