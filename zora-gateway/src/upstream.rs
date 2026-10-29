//! Upstreams at run time: a load balancer over the targets of each upstream.

use std::collections::BTreeSet;

use pingora::lb::discovery::Static;
use pingora::lb::selection::RoundRobin;
use pingora::lb::{Backend, Backends, LoadBalancer};
use zora_core::config::Upstream;

/// How many targets a selection may look at before it gives up.
const SELECT_ATTEMPTS: usize = 16;

/// An upstream ready to serve requests: its settings and a load balancer over its targets.
///
/// A new configuration reuses the runtime of an upstream whose settings did not change, so its
/// state, such as the position of the round robin, carries over.
pub(crate) struct UpstreamRuntime {
    /// Settings the runtime was built from.
    settings: Upstream,
    /// Picks the target of each request.
    balancer: LoadBalancer<RoundRobin>,
}

impl UpstreamRuntime {
    /// Builds the runtime of `settings`. It fails only if Pingora rejects a target.
    pub(crate) async fn new(settings: &Upstream) -> pingora::Result<Self> {
        let mut backends = BTreeSet::new();
        for target in &settings.targets {
            backends.insert(Backend::new_with_weight(
                &target.address.to_string(),
                target.weight as usize,
            )?);
        }
        let balancer = LoadBalancer::from_backends(Backends::new(Static::new(backends)));
        // Fills in the static targets; it does not wait for anything.
        balancer.update().await?;
        Ok(Self {
            settings: settings.clone(),
            balancer,
        })
    }

    /// Returns the settings the runtime was built from.
    pub(crate) fn settings(&self) -> &Upstream {
        &self.settings
    }

    /// Picks the target of the next request: in turn, in proportion to the weights.
    pub(crate) fn select(&self) -> Option<Backend> {
        self.balancer.select(&[], SELECT_ATTEMPTS)
    }
}
