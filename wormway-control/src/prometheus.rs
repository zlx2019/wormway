//! Prometheus output of the metrics.

use std::fmt::Write;
use std::time::{Duration, UNIX_EPOCH};

use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use wormway_runtime::{CertificateReport, TargetState, UpstreamReport};

/// Upper bounds of the buckets of every histogram, in seconds: from 5 milliseconds to a minute.
const BUCKETS: [f64; 13] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// How often the samples of the histograms move into their buckets between scrapes.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Renders the metrics of the process in the Prometheus text format.
#[derive(Clone)]
pub struct Metrics(PrometheusHandle);

impl Metrics {
    /// Installs the process-wide recorder that the `metrics` macros report to, and records the
    /// build information. Only one recorder can be installed per process. Run
    /// [`Metrics::keep_up`] next to it.
    pub fn install() -> Result<Self, MetricsError> {
        let handle = PrometheusBuilder::new()
            .set_buckets(&BUCKETS)
            .and_then(PrometheusBuilder::install_recorder)
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

    /// Moves the samples of the histograms into their buckets every few seconds, so that they
    /// do not pile up in memory when nobody scrapes. Runs until its runtime stops.
    pub async fn keep_up(self) {
        let mut interval = tokio::time::interval(UPKEEP_INTERVAL);
        loop {
            interval.tick().await;
            self.0.run_upkeep();
        }
    }

    /// Returns the metrics in the Prometheus text format.
    pub fn render(&self) -> String {
        self.0.render()
    }
}

/// Writes the gauges of the state in effect in the Prometheus text format: whether each target
/// of `upstreams` gets requests, and when each of `certificates` expires. They are computed at
/// each scrape, so that targets and certificates that are gone leave no series behind. Names
/// and addresses need no escaping in label values.
pub(crate) fn write_state(
    out: &mut String,
    upstreams: &[UpstreamReport],
    certificates: &[CertificateReport],
) {
    if upstreams
        .iter()
        .any(|upstream| !upstream.targets.is_empty())
    {
        let name = "wormway_upstream_target_healthy";
        write_family(
            out,
            name,
            "Whether a target of an upstream gets requests: 1 when its checks pass or it has none, 0 when the active checks failed or the passive checks took it out.",
        );
        for upstream in upstreams {
            for target in &upstream.targets {
                let healthy = u8::from(target.state == TargetState::Healthy);
                let (upstream, target) = (&upstream.name, target.address);
                let _ = writeln!(
                    out,
                    "{name}{{upstream=\"{upstream}\",target=\"{target}\"}} {healthy}"
                );
            }
        }
        out.push('\n');
    }
    if !certificates.is_empty() {
        let name = "wormway_certificate_expiry_timestamp_seconds";
        write_family(
            out,
            name,
            "When a certificate in effect expires, in seconds since the Unix epoch.",
        );
        for certificate in certificates {
            let expiry = certificate
                .not_after
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs());
            let _ = writeln!(
                out,
                "{name}{{certificate=\"{}\"}} {expiry}",
                certificate.name
            );
        }
        out.push('\n');
    }
}

/// Writes the help and type lines of gauge `name`.
fn write_family(out: &mut String, name: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
}

/// The recorder could not be installed, usually because another one already was.
#[derive(Debug, thiserror::Error)]
#[error("cannot install the metrics recorder")]
pub struct MetricsError(#[source] BuildError);
