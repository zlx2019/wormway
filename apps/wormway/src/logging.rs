//! Log output, Pingora's included: Pingora logs through the `log` crate, whose records are
//! passed on to `tracing` here.

use std::fmt;
use std::io::IsTerminal;
use std::time::SystemTime;

use tracing::level_filters::LevelFilter;
use tracing_log::AsLog;
use tracing_log::log::{self, Level, Log, Metadata, Record};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use wormway_core::config::{LogFormat, LogSettings};
use wormway_core::time::{Fraction, LogTime};

/// Builds the log filter from `log.level`.
pub fn filter(settings: &LogSettings) -> Result<EnvFilter, ParseError> {
    EnvFilter::try_new(&settings.level)
}

/// Sends logs to standard error in the configured format, with times in the configured format
/// and time zone, the records of the `log` crate included.
pub fn init(settings: &LogSettings) -> anyhow::Result<()> {
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter(settings)?)
        .with_writer(std::io::stderr)
        .with_timer(Timer(LogTime::new(settings)));
    let installed = match settings.format {
        LogFormat::Text => tracing::subscriber::set_global_default(
            builder.with_ansi(std::io::stderr().is_terminal()).finish(),
        ),
        LogFormat::Json => tracing::subscriber::set_global_default(builder.json().finish()),
    };
    installed.map_err(|error| anyhow::anyhow!("cannot set up logging: {error}"))?;
    log::set_boxed_logger(Box::new(Bridge))
        .map_err(|error| anyhow::anyhow!("cannot set up logging: {error}"))?;
    // Records above what the filter lets through stop in the `log` macros.
    log::set_max_level(LevelFilter::current().as_log());
    Ok(())
}

/// Writes the time of each log line as `[log]` asks, to the microsecond without a pattern.
struct Timer(LogTime);

impl FormatTime for Timer {
    /// Writes the time now.
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        self.0.write(w, SystemTime::now(), Fraction::Micros)
    }
}

/// Passes the records of the `log` crate on to `tracing`, at debug level for the errors in
/// which Pingora tells about clients that misbehaved or went away.
struct Bridge;

impl Log for Bridge {
    /// Every record goes on; the `tracing` filter decides.
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    /// Passes `record` on, at the level of [`level`].
    fn log(&self, record: &Record<'_>) {
        let level = level(record);
        // Nothing could report that a record was lost.
        let _ = if level == record.level() {
            tracing_log::format_trace(record)
        } else {
            let lowered = Record::builder()
                .level(level)
                .target(record.target())
                .args(*record.args())
                .module_path(record.module_path())
                .file(record.file())
                .line(record.line())
                .build();
            tracing_log::format_trace(&lowered)
        };
    }

    /// The `tracing` subscriber writes at once.
    fn flush(&self) {}
}

/// Returns the level to log `record` at: debug for the messages of Pingora about clients,
/// otherwise its own.
fn level(record: &Record<'_>) -> Level {
    let level = record.level();
    if level > Level::Warn || !record.target().starts_with("pingora") {
        return level;
    }
    if about_clients(record.target(), &record.args().to_string()) {
        Level::Debug
    } else {
        level
    }
}

/// Whether `message`, logged by Pingora module `target`, only tells about a client that
/// misbehaved or went away, which Nginx logs at `info`, below its default level.
fn about_clients(target: &str, message: &str) -> bool {
    // The client agreed on HTTP/2 over TLS, then sent no HTTP/2 preface.
    (target == "pingora_core::apps" && message.starts_with("H2 handshake error"))
        // The client left, or took too long, in the middle of its request header.
        || message.starts_with("Fail to proxy: Downstream")
        // The client left before the error response could reach it.
        || message.starts_with("failed to send error response to downstream")
}

#[cfg(test)]
mod tests {
    use std::fmt::Arguments;

    use super::*;

    /// The level that [`level`] gives a record of `target` at `level` with `args`.
    fn level_of(target: &str, level: Level, args: Arguments<'_>) -> Level {
        super::level(
            &Record::builder()
                .level(level)
                .target(target)
                .args(args)
                .build(),
        )
    }

    /// Messages about clients go to debug, Pingora's other messages and those of other crates
    /// keep their level.
    #[test]
    fn lowers_messages_about_clients() {
        let apps = "pingora_core::apps";
        let error = Level::Error;
        let lowered = [
            level_of(
                apps,
                error,
                format_args!("H2 handshake error {}", "connection reset"),
            ),
            level_of(
                "pingora_proxy",
                error,
                format_args!(
                    "Fail to proxy: {}, downstream session type: {}",
                    "Downstream ConnectionClosed", "HTTP/1.1"
                ),
            ),
            level_of(
                "pingora_proxy::proxy_trait",
                error,
                format_args!("failed to send error response to downstream: {}", "closed"),
            ),
        ];
        assert_eq!(lowered, [Level::Debug; 3]);
        let kept = [
            level_of(apps, error, format_args!("TLS accept error")),
            level_of(
                "pingora_proxy",
                error,
                format_args!("Fail to proxy: Upstream"),
            ),
            level_of("wormway", error, format_args!("H2 handshake error")),
            level_of(apps, Level::Info, format_args!("H2 handshake error")),
        ];
        assert_eq!(kept, [error, error, error, Level::Info]);
    }
}
