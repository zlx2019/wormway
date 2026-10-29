//! Snapshots of the routes and upstreams, and the engine that compiles one from each
//! configuration.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use zora_core::config::{Config, Issue, Name, Protocol, Upstream};
use zora_core::routing::Router;
use zora_runtime::{BoxFuture, Engine, Staged};

use crate::upstream::UpstreamRuntime;

/// Most targets of one upstream: Pingora's load balancer indexes them with 16 bits.
const MAX_TARGETS: usize = u16::MAX as usize;

/// The routes and upstreams of one configuration, ready to serve requests. It never changes: a
/// new configuration compiles a new snapshot.
#[derive(Default)]
pub(crate) struct GatewaySnapshot {
    /// The router of each HTTP listener.
    routers: HashMap<Name, Router<Arc<CompiledRoute>>>,
    /// Upstreams by name. The next compilation reuses the ones whose settings stay the same.
    upstreams: BTreeMap<Name, Arc<UpstreamRuntime>>,
}

/// A route ready to serve requests.
pub(crate) struct CompiledRoute {
    /// Upstream that serves the requests.
    pub(crate) upstream: Arc<UpstreamRuntime>,
}

impl GatewaySnapshot {
    /// Returns the route of a request on `listener` for `host` and `path`.
    pub(crate) fn route(
        &self,
        listener: &str,
        host: Option<&str>,
        path: &str,
    ) -> Option<&Arc<CompiledRoute>> {
        self.routers.get(listener)?.find(host, path)
    }

    /// Compiles `config`, reusing the upstreams of `self` whose settings did not change.
    async fn compile(&self, config: &Config) -> Result<Self, Vec<Issue>> {
        let mut issues = Vec::new();
        let mut upstreams = BTreeMap::new();
        for (name, settings) in &config.upstreams {
            match self.upstream(name, settings).await {
                Ok(runtime) => {
                    upstreams.insert(name.clone(), runtime);
                }
                Err(issue) => issues.push(issue),
            }
        }
        if !issues.is_empty() {
            return Err(issues);
        }

        // Validation made sure that every route names an existing upstream.
        let routes: Vec<_> = config
            .routes
            .values()
            .filter_map(|route| {
                let upstream = upstreams.get(&route.upstream)?.clone();
                Some((route, Arc::new(CompiledRoute { upstream })))
            })
            .collect();
        let routers = config
            .listeners
            .iter()
            .filter(|(_, listener)| listener.protocol == Protocol::Http)
            .map(|(listener, _)| {
                let own = routes.iter().filter(|(route, _)| {
                    route.listeners.is_empty() || route.listeners.contains(listener)
                });
                let router =
                    Router::new(own.map(|(route, compiled)| (&route.r#match, compiled.clone())));
                (listener.clone(), router)
            })
            .collect();
        Ok(Self { routers, upstreams })
    }

    /// Returns the runtime of upstream `name`: the running one if its settings are the same,
    /// otherwise a new one.
    async fn upstream(
        &self,
        name: &Name,
        settings: &Upstream,
    ) -> Result<Arc<UpstreamRuntime>, Issue> {
        if let Some(running) = self.upstreams.get(name)
            && running.settings() == settings
        {
            return Ok(running.clone());
        }
        let path = format!("upstreams.{name}.targets");
        if settings.targets.len() > MAX_TARGETS {
            return Err(Issue::new(
                path,
                format!("at most {MAX_TARGETS} targets are supported"),
            ));
        }
        match UpstreamRuntime::new(settings).await {
            Ok(runtime) => Ok(Arc::new(runtime)),
            Err(error) => Err(Issue::new(path, error.to_string())),
        }
    }
}

/// The engine of the gateway: compiles the routes and upstreams of each configuration into a
/// snapshot, and publishes it when the change commits.
pub(crate) struct Routing {
    /// Where the snapshot in effect is published.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
}

impl Routing {
    /// Creates the engine that publishes to `snapshot`.
    pub(crate) fn new(snapshot: Arc<ArcSwap<GatewaySnapshot>>) -> Self {
        Self { snapshot }
    }
}

impl Engine for Routing {
    /// Compiles `config` against the snapshot in effect.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            let next = self.snapshot.load_full().compile(config).await?;
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
    use super::*;

    /// Parses a configuration, adding `version = 1` in front.
    fn parse(text: &str) -> Config {
        Config::from_toml(&format!("version = 1\n{text}")).unwrap()
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
            .compile(&parse(BASE))
            .await
            .unwrap();
        assert!(snapshot.route("web", Some("example.com"), "/").is_some());
        assert!(snapshot.route("api", Some("example.com"), "/").is_none());
        assert!(snapshot.route("missing", None, "/").is_none());

        let everywhere = BASE.replace("listeners = [\"web\"]\n", "");
        let snapshot = GatewaySnapshot::default()
            .compile(&parse(&everywhere))
            .await
            .unwrap();
        assert!(snapshot.route("api", None, "/").is_some());
    }

    /// Upstreams whose settings stay the same are reused; changed ones are rebuilt.
    #[tokio::test]
    async fn reuses_unchanged_upstreams() {
        let first = GatewaySnapshot::default()
            .compile(&parse(BASE))
            .await
            .unwrap();
        let changed = BASE.replace("127.0.0.1:9002", "127.0.0.1:9003");
        let second = first.compile(&parse(&changed)).await.unwrap();
        assert!(Arc::ptr_eq(
            &first.upstreams["app"],
            &second.upstreams["app"]
        ));
        assert!(!Arc::ptr_eq(
            &first.upstreams["other"],
            &second.upstreams["other"]
        ));
        let route = second.route("web", None, "/").unwrap();
        assert!(Arc::ptr_eq(&route.upstream, &second.upstreams["app"]));
    }
}
