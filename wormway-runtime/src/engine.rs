//! Engines: state built from the configuration, such as the routing table of the gateway, that
//! switches together with the listeners.

use wormway_core::config::{Config, Issue};

use crate::service::BoxFuture;

/// Builds state from each configuration and puts it in effect together with the listeners.
///
/// A change prepares every engine before anything switches, so a problem in any of them leaves
/// the running configuration as it was. The state of every engine is committed before new
/// listeners start accepting.
pub trait Engine: Send + Sync + 'static {
    /// Builds the state for `config` without changing what runs. Problems reject the whole
    /// change, each with the path of the setting it concerns.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>>;
}

/// State built by [`Engine::prepare`]. Committing puts it in effect; dropping it discards it.
pub trait Staged: Send {
    /// Puts the state in effect. It cannot fail.
    fn commit(self: Box<Self>);
}
