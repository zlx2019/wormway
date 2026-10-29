//! Configurations in effect.

use wormway_core::config::Config;

/// A configuration in effect.
///
/// Code that serves a request takes the current snapshot when the request starts and keeps it
/// until the request ends, so every request sees one consistent configuration.
#[derive(Debug)]
pub struct Snapshot {
    /// Starts at 1 and grows by one with every applied configuration.
    pub version: u64,
    /// The configuration.
    pub config: Config,
}
