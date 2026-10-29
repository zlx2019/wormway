//! Metrics recorded by the runtime. They go to the process-wide recorder, if one is installed.

use metrics::{Counter, Gauge, counter, describe_counter, describe_gauge, gauge};
use wormway_core::config::Name;

/// Connections accepted, by listener.
const CONNECTIONS_TOTAL: &str = "wormway_connections_total";
/// Connections open, by listener.
const CONNECTIONS_ACTIVE: &str = "wormway_connections_active";
/// Configuration changes, by result.
const CONFIG_APPLIES_TOTAL: &str = "wormway_config_applies_total";

/// Registers the help text of every runtime metric.
pub(crate) fn describe() {
    describe_counter!(CONNECTIONS_TOTAL, "Connections accepted, by listener.");
    describe_gauge!(CONNECTIONS_ACTIVE, "Connections open, by listener.");
    describe_counter!(
        CONFIG_APPLIES_TOTAL,
        "Configuration changes, by result (ok or error)."
    );
}

/// Handles to the connection metrics of one listener, looked up once instead of per
/// connection.
pub(crate) fn connections(listener: &Name) -> (Counter, Gauge) {
    let label = listener.to_string();
    (
        counter!(CONNECTIONS_TOTAL, "listener" => label.clone()),
        gauge!(CONNECTIONS_ACTIVE, "listener" => label),
    )
}

/// Counts one configuration change that succeeded or failed.
pub(crate) fn config_applied(ok: bool) {
    let result = if ok { "ok" } else { "error" };
    counter!(CONFIG_APPLIES_TOTAL, "result" => result).increment(1);
}
