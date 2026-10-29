//! Prometheus output of the metrics.

use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};

/// Renders the metrics of the process in the Prometheus text format.
#[derive(Clone)]
pub struct Metrics(PrometheusHandle);

impl Metrics {
    /// Installs the process-wide recorder that the `metrics` macros report to, and records the
    /// build information. Only one recorder can be installed per process.
    pub fn install() -> Result<Self, MetricsError> {
        let handle = PrometheusBuilder::new()
            .install_recorder()
            .map_err(MetricsError)?;
        metrics::describe_gauge!(
            "wormway_build_info",
            "Always 1, labeled with the Wormway version."
        );
        metrics::gauge!("wormway_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
        Ok(Self(handle))
    }

    /// Creates a recorder that is not installed, so nothing reports to it. For tests.
    pub fn detached() -> Self {
        Self(PrometheusBuilder::new().build_recorder().handle())
    }

    /// Returns the metrics in the Prometheus text format.
    pub fn render(&self) -> String {
        self.0.render()
    }
}

/// The recorder could not be installed, usually because another one already was.
#[derive(Debug, thiserror::Error)]
#[error("cannot install the metrics recorder")]
pub struct MetricsError(#[source] BuildError);
