//! Log output.

use std::io::IsTerminal;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;
use zora_core::config::{LogFormat, LogSettings};

/// Builds the log filter from `log.level`.
pub fn filter(settings: &LogSettings) -> Result<EnvFilter, ParseError> {
    EnvFilter::try_new(&settings.level)
}

/// Sends logs to standard error in the configured format.
pub fn init(settings: &LogSettings) -> anyhow::Result<()> {
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter(settings)?)
        .with_writer(std::io::stderr);
    let installed = match settings.format {
        LogFormat::Text => builder
            .with_ansi(std::io::stderr().is_terminal())
            .try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    installed.map_err(|error| anyhow::anyhow!("cannot set up logging: {error}"))
}
