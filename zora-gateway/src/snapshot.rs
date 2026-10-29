//! Snapshots of the routes and upstreams, and the engine that compiles one from each
//! configuration.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use zora_core::config::{Config, Issue, Name, Protocol, Upstream};
use zora_core::routing::{Request, Router};
use zora_runtime::{BoxFuture, Engine, Staged};
use zora_tls::Certificates;

use crate::route::CompiledRoute;
use crate::upstream::{CompiledUpstream, UpstreamRuntime};
use crate::upstream_tls::PeerTls;

/// Most targets of one upstream: Pingora's load balancer indexes them with 16 bits.
const MAX_TARGETS: usize = u16::MAX as usize;

/// The routes and upstreams of one configuration, ready to serve requests. It never changes: a
/// new configuration compiles a new snapshot.
#[derive(Default)]
pub(crate) struct GatewaySnapshot {
    /// The router of each HTTP listener.
    routers: HashMap<Name, Router<Arc<CompiledRoute>>>,
    /// Upstreams by name. The next compilation reuses the runtimes whose targets and balancing
    /// stay the same.
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

    /// Compiles `config`, reusing the upstream runtimes of `self` whose targets and balancing
    /// did not change. The TLS files of upstreams are read again, relative to the configuration
    /// file of `certificates`.
    async fn compile(
        &self,
        config: &Config,
        certificates: &Certificates,
    ) -> Result<Self, Vec<Issue>> {
        let mut issues = Vec::new();
        let mut upstreams = BTreeMap::new();
        for (name, settings) in &config.upstreams {
            let tls = match &settings.tls {
                Some(tls) => PeerTls::load(name, tls, certificates).await.map(Some),
                None => Ok(None),
            };
            match (self.upstream(name, settings).await, tls) {
                (Ok(runtime), Ok(tls)) => {
                    let compiled = CompiledUpstream::new(runtime, settings, tls);
                    upstreams.insert(name.clone(), Arc::new(compiled));
                }
                (runtime, tls) => {
                    issues.extend(runtime.err().into_iter().flatten());
                    issues.extend(tls.err().into_iter().flatten());
                }
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

    /// Returns the runtime of upstream `name`: the running one if its targets and balancing are
    /// the same, otherwise a new one, with its host names resolved.
    async fn upstream(
        &self,
        name: &Name,
        settings: &Upstream,
    ) -> Result<Arc<UpstreamRuntime>, Vec<Issue>> {
        if let Some(running) = self.upstreams.get(name)
            && running.runtime.serves(settings)
        {
            return Ok(running.runtime.clone());
        }
        let path = format!("upstreams.{name}.targets");
        if settings.targets.len() > MAX_TARGETS {
            return Err(vec![Issue::new(
                path,
                format!("at most {MAX_TARGETS} targets are supported"),
            )]);
        }
        UpstreamRuntime::new(name, settings)
            .await
            .map_err(|problems| {
                problems
                    .into_iter()
                    .map(|(index, problem)| Issue::new(format!("{path}[{index}]"), problem))
                    .collect()
            })
    }
}

/// The engine of the gateway: compiles the routes and upstreams of each configuration into a
/// snapshot, and publishes it when the change commits.
pub(crate) struct Routing {
    /// Where the snapshot in effect is published.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Reads the TLS files of upstreams, relative to the configuration file.
    certificates: Certificates,
}

impl Routing {
    /// Creates the engine that publishes to `snapshot` and reads TLS files with
    /// `certificates`.
    pub(crate) fn new(snapshot: Arc<ArcSwap<GatewaySnapshot>>, certificates: Certificates) -> Self {
        Self {
            snapshot,
            certificates,
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
                .compile(config, &self.certificates)
                .await?;
            let staged: Box<dyn Staged> = Box::new(Compiled {
                target: self.snapshot.clone(),
                next: Arc::new(next),
            });
            Ok(staged)
        })
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
    /// Publishes the snapshot. Requests in flight keep the one they started with.
    fn commit(self: Box<Self>) {
        self.target.store(self.next);
    }
}

#[cfg(test)]
mod tests {
    use zora_core::routing::RequestHeaders;

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
            .compile(&parse(BASE), &files())
            .await
            .unwrap();
        assert!(route(&snapshot, "web", Some("example.com")).is_some());
        assert!(route(&snapshot, "api", Some("example.com")).is_none());
        assert!(route(&snapshot, "missing", None).is_none());

        let everywhere = BASE.replace("listeners = [\"web\"]\n", "");
        let snapshot = GatewaySnapshot::default()
            .compile(&parse(&everywhere), &files())
            .await
            .unwrap();
        assert!(route(&snapshot, "api", None).is_some());
    }

    /// Upstreams whose targets and balancing stay the same keep their runtime, whatever else
    /// changes; changed ones get a new runtime.
    #[tokio::test]
    async fn reuses_unchanged_upstreams() {
        let first = GatewaySnapshot::default()
            .compile(&parse(BASE), &files())
            .await
            .unwrap();
        let changed = BASE.replace("127.0.0.1:9002", "127.0.0.1:9003").replace(
            "targets = [\"127.0.0.1:9001\"]",
            "targets = [\"127.0.0.1:9001\"]\nretries = 0",
        );
        let second = first.compile(&parse(&changed), &files()).await.unwrap();
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
        let third = second.compile(&parse(&balanced), &files()).await.unwrap();
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
            .compile(&parse(&unknown), &files())
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
            .compile(&parse(&broken), &files())
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
