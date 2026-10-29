//! Snapshots of the routes and upstreams, and the engine that compiles one from each
//! configuration.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use wormway_core::config::{Config, HealthCheckKind, Issue, Name, Protocol, Upstream};
use wormway_core::routing::{Request, Router};
use wormway_runtime::{BoxFuture, Engine, HealthReport, Staged, UpstreamReport};
use wormway_tls::Certificates;

use crate::health::UpstreamHealth;
use crate::probe::Prober;
use crate::route::CompiledRoute;
use crate::upstream::{self, CompiledUpstream, Connect, UpstreamRuntime};
use crate::upstream_tls::PeerTls;

/// Most targets of one upstream: Pingora's load balancer indexes them with 16 bits.
const MAX_TARGETS: usize = u16::MAX as usize;

/// The routes and upstreams of one configuration, ready to serve requests. It never changes: a
/// new configuration compiles a new snapshot.
#[derive(Default)]
pub(crate) struct GatewaySnapshot {
    /// The router of each HTTP listener.
    routers: HashMap<Name, Router<Arc<CompiledRoute>>>,
    /// Upstreams by name. The next compilation reuses the runtimes whose targets, balancing and
    /// health checks stay the same.
    upstreams: BTreeMap<Name, Arc<CompiledUpstream>>,
}

impl GatewaySnapshot {
    /// Returns the route of `request` on `listener`.
    pub(crate) fn route(
        &self,
        listener: &str,
        request: &Request<'_>,
    ) -> Option<&Arc<CompiledRoute>> {
        self.routers.get(listener)?.find(request)
    }

    /// Returns the upstreams in name order, with the health of their targets.
    fn report(&self) -> Vec<UpstreamReport> {
        self.upstreams
            .values()
            .map(|upstream| upstream.runtime.report())
            .collect()
    }

    /// Compiles `config`, reusing the upstream runtimes of `self` whose targets, balancing and
    /// health checks did not change. The TLS files of upstreams are read again, relative to the
    /// configuration file of `certificates`; `prober` makes the probes of the health checks.
    async fn compile(
        &self,
        config: &Config,
        certificates: &Certificates,
        prober: &Arc<Prober>,
    ) -> Result<Self, Vec<Issue>> {
        let mut issues = Vec::new();
        let mut upstreams = BTreeMap::new();
        for (name, settings) in &config.upstreams {
            let tls = match &settings.tls {
                Some(tls) => PeerTls::load(name, tls, certificates).await.map(Some),
                None => Ok(None),
            };
            let connect = match tls {
                Ok(tls) => Arc::new(Connect::new(settings.protocol(), tls)),
                Err(problems) => {
                    // Report the targets that do not resolve as well.
                    if let Err(targets) = upstream::resolve(&settings.targets).await {
                        issues.extend(target_issues(name, targets));
                    }
                    issues.extend(problems);
                    continue;
                }
            };
            match self.upstream(name, settings, &connect, prober).await {
                Ok(runtime) => {
                    let compiled = CompiledUpstream::new(runtime, settings, connect);
                    upstreams.insert(name.clone(), Arc::new(compiled));
                }
                Err(problems) => issues.extend(problems),
            }
        }
        if !issues.is_empty() {
            return Err(issues);
        }

        let mut routes = Vec::new();
        for (name, route) in &config.routes {
            match CompiledRoute::new(name, route, &upstreams) {
                Ok(compiled) => routes.push((route, Arc::new(compiled))),
                Err(issue) => issues.push(issue),
            }
        }
        if !issues.is_empty() {
            return Err(issues);
        }
        let routers = config
            .listeners
            .iter()
            .filter(|(_, listener)| listener.protocol == Protocol::Http)
            .map(|(listener, _)| {
                let own = routes.iter().filter(|(route, _)| {
                    route.listeners.is_empty() || route.listeners.contains(listener)
                });
                let router = Router::new(own.map(|(route, compiled)| (*route, compiled.clone())));
                (listener.clone(), router)
            })
            .collect();
        Ok(Self { routers, upstreams })
    }

    /// Returns the runtime of upstream `name`: the running one if its targets, balancing and
    /// health checks are the same, otherwise a new one, with its host names resolved. A new
    /// runtime keeps the health of the running one while the health checks stay the same, and
    /// probes its targets that were never probed through `connect`.
    async fn upstream(
        &self,
        name: &Name,
        settings: &Upstream,
        connect: &Arc<Connect>,
        prober: &Arc<Prober>,
    ) -> Result<Arc<UpstreamRuntime>, Vec<Issue>> {
        let running = self.upstreams.get(name).map(|running| &running.runtime);
        if let Some(running) = running
            && running.serves(settings)
        {
            return Ok(running.clone());
        }
        if settings.targets.len() > MAX_TARGETS {
            return Err(vec![Issue::new(
                format!("upstreams.{name}.targets"),
                format!("at most {MAX_TARGETS} targets are supported"),
            )]);
        }
        let health = match running.and_then(|running| running.health()) {
            Some(health) if health.checks_as(settings) => Some(health.clone()),
            _ => {
                let http = settings
                    .health_check
                    .as_ref()
                    .is_some_and(|check| check.kind == HealthCheckKind::Http);
                if http && let Err(problem) = prober.connector().await {
                    let at = format!("upstreams.{name}.health_check");
                    return Err(vec![Issue::new(at, problem)]);
                }
                UpstreamHealth::new(name, settings, prober.clone(), connect.clone())
            }
        };
        UpstreamRuntime::new(name, settings, health, connect)
            .await
            .map_err(|problems| target_issues(name, problems))
    }
}

/// Returns the problems with the targets of upstream `name`, which come with the index of
/// their target.
fn target_issues(name: &Name, problems: Vec<(usize, String)>) -> Vec<Issue> {
    problems
        .into_iter()
        .map(|(index, problem)| Issue::new(format!("upstreams.{name}.targets[{index}]"), problem))
        .collect()
}

/// The engine of the gateway: compiles the routes and upstreams of each configuration into a
/// snapshot, and publishes it when the change commits.
pub(crate) struct Routing {
    /// Where the snapshot in effect is published.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Reads the TLS files of upstreams, relative to the configuration file.
    certificates: Certificates,
    /// Makes the probes of the health checks of every upstream.
    prober: Arc<Prober>,
}

impl Routing {
    /// Creates the engine that publishes to `snapshot` and reads TLS files with
    /// `certificates`.
    pub(crate) fn new(snapshot: Arc<ArcSwap<GatewaySnapshot>>, certificates: Certificates) -> Self {
        Self {
            snapshot,
            certificates,
            prober: Arc::default(),
        }
    }
}

impl Engine for Routing {
    /// Compiles `config` against the snapshot in effect.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            let next = self
                .snapshot
                .load_full()
                .compile(config, &self.certificates, &self.prober)
                .await?;
            let staged: Box<dyn Staged> = Box::new(Compiled {
                target: self.snapshot.clone(),
                next: Arc::new(next),
            });
            Ok(staged)
        })
    }
}

/// Reports the health of the upstreams of the snapshot in effect.
pub(crate) struct Report(pub(crate) Arc<ArcSwap<GatewaySnapshot>>);

impl HealthReport for Report {
    /// Returns the upstreams of the snapshot in effect.
    fn upstreams(&self) -> Vec<UpstreamReport> {
        self.0.load().report()
    }
}

/// A compiled snapshot waiting to be published.
struct Compiled {
    /// Where to publish it.
    target: Arc<ArcSwap<GatewaySnapshot>>,
    /// The snapshot.
    next: Arc<GatewaySnapshot>,
}

impl Staged for Compiled {
    /// Publishes the snapshot, and hands the TLS settings it read to the health checks.
    /// Requests in flight keep the snapshot they started with.
    fn commit(self: Box<Self>) {
        for upstream in self.next.upstreams.values() {
            upstream.publish();
        }
        self.target.store(self.next);
    }
}

#[cfg(test)]
mod tests {
    use wormway_core::routing::RequestHeaders;

    use super::*;

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

    /// Reads TLS files relative to the working directory.
    fn files() -> Certificates {
        Certificates::new(".")
    }

    /// Makes no probes until a test asks for health checks.
    fn prober() -> Arc<Prober> {
        Arc::default()
    }

    /// Parses a configuration, adding `version = 1` in front.
    fn parse(text: &str) -> Config {
        Config::from_toml(&format!("version = 1\n{text}")).unwrap()
    }

    /// The route of `GET /` for `host` on `listener`.
    fn route<'a>(
        snapshot: &'a GatewaySnapshot,
        listener: &str,
        host: Option<&str>,
    ) -> Option<&'a Arc<CompiledRoute>> {
        let request = Request {
            host,
            path: b"/",
            method: "GET",
            headers: &NoHeaders,
        };
        snapshot.route(listener, &request)
    }

    /// Two listeners and an upstream that a route of one listener uses.
    const BASE: &str = r#"
        [listeners.web]
        listen = ["127.0.0.1:0"]
        protocol = "http"
        [listeners.api]
        listen = ["127.0.0.1:0"]
        protocol = "http"
        [routes.app]
        listeners = ["web"]
        upstream = "app"
        [upstreams.app]
        targets = ["127.0.0.1:9001"]
        [upstreams.other]
        targets = ["127.0.0.1:9002"]
    "#;

    /// Each listener gets the routes meant for it, and routes without listeners go to all.
    #[tokio::test]
    async fn gives_each_listener_its_routes() {
        let snapshot = GatewaySnapshot::default()
            .compile(&parse(BASE), &files(), &prober())
            .await
            .unwrap();
        assert!(route(&snapshot, "web", Some("example.com")).is_some());
        assert!(route(&snapshot, "api", Some("example.com")).is_none());
        assert!(route(&snapshot, "missing", None).is_none());

        let everywhere = BASE.replace("listeners = [\"web\"]\n", "");
        let snapshot = GatewaySnapshot::default()
            .compile(&parse(&everywhere), &files(), &prober())
            .await
            .unwrap();
        assert!(route(&snapshot, "api", None).is_some());
    }

    /// Upstreams whose targets and balancing stay the same keep their runtime, whatever else
    /// changes; changed ones get a new runtime.
    #[tokio::test]
    async fn reuses_unchanged_upstreams() {
        let first = GatewaySnapshot::default()
            .compile(&parse(BASE), &files(), &prober())
            .await
            .unwrap();
        let changed = BASE.replace("127.0.0.1:9002", "127.0.0.1:9003").replace(
            "targets = [\"127.0.0.1:9001\"]",
            "targets = [\"127.0.0.1:9001\"]\nretries = 0",
        );
        let second = first
            .compile(&parse(&changed), &files(), &prober())
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &first.upstreams["app"].runtime,
            &second.upstreams["app"].runtime
        ));
        assert_eq!(second.upstreams["app"].retries(), 0);
        assert!(!Arc::ptr_eq(
            &first.upstreams["other"].runtime,
            &second.upstreams["other"].runtime
        ));
        let balanced = changed.replace("retries = 0", "balance = \"least_conn\"");
        let third = second
            .compile(&parse(&balanced), &files(), &prober())
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(
            &second.upstreams["app"].runtime,
            &third.upstreams["app"].runtime
        ));
        let found = route(&second, "web", None).unwrap();
        assert!(Arc::ptr_eq(
            found.upstream().unwrap(),
            &second.upstreams["app"]
        ));
    }

    /// A host name that does not resolve rejects the configuration, at its target.
    #[tokio::test]
    async fn rejects_names_that_do_not_resolve() {
        let unknown = BASE.replace("127.0.0.1:9002", "unknown.invalid:9002");
        let issues = GatewaySnapshot::default()
            .compile(&parse(&unknown), &files(), &prober())
            .await
            .err()
            .unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].path, "upstreams.other.targets[0]");
        assert!(issues[0].message.contains("unknown.invalid"), "{issues:?}");
    }

    /// TLS files that cannot be read reject the configuration at their setting, together with
    /// the other problems of the upstream.
    #[tokio::test]
    async fn rejects_unreadable_tls_files() {
        let broken = BASE.replace(
            "targets = [\"127.0.0.1:9002\"]",
            "targets = [\"unknown.invalid:9002\"]\n\
             tls = { ca = \"missing-ca.pem\", cert = \"missing.crt\", key = \"missing.key\" }",
        );
        let issues = GatewaySnapshot::default()
            .compile(&parse(&broken), &files(), &prober())
            .await
            .err()
            .unwrap();
        let paths: Vec<&str> = issues.iter().map(|issue| issue.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "upstreams.other.targets[0]",
                "upstreams.other.tls.ca",
                "upstreams.other.tls.cert",
            ]
        );
        assert!(issues[1].message.contains("missing-ca.pem"), "{issues:?}");
    }
}
