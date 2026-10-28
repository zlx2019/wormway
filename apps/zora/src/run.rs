//! `zora run`: serves until a shutdown signal and reloads the configuration file on SIGHUP.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use tokio::runtime::{Builder, Handle, Runtime};
use tracing::{error, info, warn};
use zora_core::config::{Config, ConfigError, ConfigSource};
use zora_runtime::{Server, Services};

use crate::load;
use crate::logging;
use crate::signals::{Signal, Signals};

/// Runs zora with the configuration file at `path`.
pub fn run(path: &Path) -> anyhow::Result<ExitCode> {
    let config = match load::load(path)? {
        Ok(config) => config,
        Err(error) => {
            load::print_errors(path, &error);
            return Ok(ExitCode::FAILURE);
        }
    };
    logging::init(&config.log)?;
    let data_plane = data_plane(config.server.threads)?;
    // Signals and reloads run on their own small runtime, away from the connections.
    let control_plane = Builder::new_current_thread().enable_all().build()?;
    let exit = control_plane.block_on(serve(path, config, data_plane.handle().clone()));
    // Connections have finished or were closed by now; do not wait for anything left over.
    data_plane.shutdown_timeout(Duration::from_secs(1));
    exit
}

/// Builds the runtime that serves connections, with one worker per CPU core unless `threads`
/// is set.
fn data_plane(threads: usize) -> std::io::Result<Runtime> {
    let mut builder = Builder::new_multi_thread();
    builder.enable_all().thread_name("zora-worker");
    if threads > 0 {
        builder.worker_threads(threads);
    }
    builder.build()
}

/// Service factories of the protocols built into this binary. None yet, so every listener is
/// rejected.
fn services() -> Services {
    Services::new()
}

/// Serves until a shutdown signal. A second shutdown signal closes open connections at once.
async fn serve(path: &Path, mut config: Config, data_plane: Handle) -> anyhow::Result<ExitCode> {
    // Install the handlers first: until then SIGHUP would end the process.
    let mut signals = Signals::new()?;
    info!("zora {} starting", env!("CARGO_PKG_VERSION"));
    for warning in config.warnings() {
        warn!("{warning}");
    }
    if config.config.source == ConfigSource::Db {
        warn!("dynamic settings from the database are not supported yet, starting without them");
        config.clear_dynamic();
    }
    let server = match Server::start(data_plane, services(), config) {
        Ok(server) => server,
        Err(error) => {
            error!("cannot start: {:#}", anyhow::Error::from(error));
            return Ok(ExitCode::FAILURE);
        }
    };
    info!(
        config_version = server.snapshot().version,
        listeners = server.listeners().len(),
        "zora is ready"
    );

    while signals.next().await == Signal::Reload {
        reload(&server, path).await;
    }
    info!("shutting down, waiting for open connections to finish");
    tokio::select! {
        () = server.shutdown() => {
            info!("stopped");
            Ok(ExitCode::SUCCESS)
        }
        () = next_shutdown(&mut signals) => {
            warn!("second shutdown signal, closing open connections now");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Waits for a shutdown signal, ignoring reloads.
async fn next_shutdown(signals: &mut Signals) {
    while signals.next().await != Signal::Shutdown {}
}

/// Rereads the configuration file and applies its dynamic settings. On any problem the
/// configuration in effect stays and the problem is logged.
async fn reload(server: &Server, path: &Path) {
    let running = server.snapshot();
    if running.config.config.source != ConfigSource::File {
        info!("SIGHUP ignored: dynamic settings come from the database (config.source = \"db\")");
        return;
    }
    info!(file = %path.display(), "reloading");
    let file = match read_in_background(path.to_owned()).await {
        Ok(Ok(file)) => file,
        Ok(Err(error)) => {
            error!("reload failed, keeping the running configuration: {error}");
            return;
        }
        Err(error) => {
            error!("reload failed, keeping the running configuration: {error:#}");
            return;
        }
    };
    if !running.config.same_static(&file) {
        warn!("static settings changed in the file, they take effect after a restart");
    }
    let mut next = running.config.clone();
    next.replace_dynamic(file);
    match server.apply(next) {
        Ok(snapshot) => info!(
            config_version = snapshot.version,
            listeners = server.listeners().len(),
            "configuration reloaded"
        ),
        Err(error) => error!(
            "reload failed, keeping the running configuration: {:#}",
            anyhow::Error::from(error)
        ),
    }
}

/// Loads the configuration file on the blocking thread pool, so file I/O does not stall the
/// runtime.
async fn read_in_background(path: PathBuf) -> anyhow::Result<Result<Config, ConfigError>> {
    tokio::task::spawn_blocking(move || load::load(&path)).await?
}
