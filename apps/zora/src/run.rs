//! `zora run`: serves until a shutdown signal and reloads the configuration file on SIGHUP.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zora_control::{Admin, AdminToken, Metrics, Store};
use zora_core::config::{AdminSettings, Config, ConfigError, ConfigSource, DynamicConfig};
use zora_gateway::Gateway;
use zora_runtime::{Server, Services};

use crate::signals::{Signal, Signals};
use crate::{ADMIN_TOKEN_ENV, load, logging};

/// Name of the database file in the data directory.
const DATABASE_FILE: &str = "zora.db";
/// How long the Admin API may take to finish its requests on shutdown.
const ADMIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the control plane starts from.
struct Setup {
    /// Configuration file, reread on SIGHUP.
    path: PathBuf,
    /// The configuration read at startup.
    config: Config,
    /// Directory of the database.
    data_dir: PathBuf,
    /// Token of the Admin API.
    token: AdminToken,
    /// Prometheus output of the metrics.
    metrics: Metrics,
}

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
    info!("zora {} starting", env!("CARGO_PKG_VERSION"));
    let data_dir = load::data_dir(path, &config);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("cannot create the data directory {}", data_dir.display()))?;
    let setup = Setup {
        path: path.to_owned(),
        token: admin_token(&data_dir, &config.admin)?,
        metrics: Metrics::install()?,
        config,
        data_dir,
    };

    let data_plane = data_plane(setup.config.server.threads)?;
    // Signals, reloads and the Admin API run on their own small runtime, away from the
    // connections.
    let control_plane = Builder::new_current_thread().enable_all().build()?;
    let exit = control_plane.block_on(serve(setup, data_plane.handle().clone()));
    // Connections have finished or were closed by now; do not wait for anything left over.
    data_plane.shutdown_timeout(Duration::from_secs(1));
    exit
}

/// Returns the Admin API token: from the environment if set, otherwise from the token file,
/// which is created on first start. A relative token file is relative to the data directory.
fn admin_token(data_dir: &Path, settings: &AdminSettings) -> anyhow::Result<AdminToken> {
    if let Ok(token) = std::env::var(ADMIN_TOKEN_ENV) {
        info!("Admin API token taken from {ADMIN_TOKEN_ENV}");
        return AdminToken::new(&token).with_context(|| format!("{ADMIN_TOKEN_ENV} is not usable"));
    }
    let file = data_dir.join(&settings.token_file);
    let (token, created) = AdminToken::load_or_create(&file)
        .with_context(|| format!("cannot use the token file {}", file.display()))?;
    if created {
        info!(file = %file.display(), "created a new Admin API token");
    } else {
        info!(file = %file.display(), "Admin API token loaded");
    }
    Ok(token)
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

/// Service factories and engines of the protocols built into this binary: the HTTP gateway.
/// `threads` is the number of data-plane workers.
fn services(threads: usize) -> Services {
    let mut services = Services::new();
    Gateway::new(threads).register(&mut services);
    services
}

/// Serves until a shutdown signal. A second shutdown signal closes open connections at once.
async fn serve(setup: Setup, data_plane: Handle) -> anyhow::Result<ExitCode> {
    // Install the handlers first: until then SIGHUP would end the process.
    let mut signals = Signals::new()?;
    let Setup {
        path,
        mut config,
        data_dir,
        token,
        metrics,
    } = setup;
    for warning in config.warnings() {
        warn!("{warning}");
    }
    let admin_addr = config.admin.listen;
    let store = Store::open(&data_dir.join(DATABASE_FILE)).await?;
    if config.config.source == ConfigSource::Db {
        config.set_dynamic(saved_dynamic(&store).await?);
    }
    let threads = data_plane.metrics().num_workers();
    let server = Arc::new(Server::start(data_plane, services(threads), config).await?);
    let admin = Admin::new(server.clone(), store.clone(), token, metrics).await?;
    let listener = TcpListener::bind(admin_addr)
        .await
        .with_context(|| format!("cannot listen on {admin_addr} for the Admin API"))?;
    let local = listener.local_addr()?;
    info!(addr = %local, "Admin API listening");
    info!("dashboard at http://{local}/ui/");
    if !admin_addr.ip().is_loopback() {
        warn!(
            addr = %admin_addr,
            "the Admin API is reachable from the network without TLS, so its token travels in clear text"
        );
    }
    let (stop_admin, admin_stopped) = oneshot::channel::<()>();
    let admin_task = tokio::spawn(zora_control::serve(listener, admin, async {
        let _ = admin_stopped.await;
    }));
    info!(
        config_version = server.snapshot().version,
        listeners = server.listeners().await.len(),
        "zora is ready"
    );

    while signals.next().await == Signal::Reload {
        reload(&server, &path).await;
    }
    info!("shutting down, waiting for open connections to finish");
    let stopped = async {
        // The Admin API stops first, so that no change arrives during the drain.
        let _ = stop_admin.send(());
        stop_admin_api(admin_task).await;
        server.shutdown().await;
        store.close().await;
    };
    tokio::select! {
        () = stopped => {
            info!("stopped");
            Ok(ExitCode::SUCCESS)
        }
        () = next_shutdown(&mut signals) => {
            warn!("second shutdown signal, closing open connections now");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Waits for the Admin API to finish its requests, and closes the rest after
/// `ADMIN_SHUTDOWN_TIMEOUT`, so a slow client cannot hold up the shutdown.
async fn stop_admin_api(mut task: JoinHandle<std::io::Result<()>>) {
    match tokio::time::timeout(ADMIN_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => warn!(%error, "the Admin API stopped with an error"),
        Ok(Err(error)) => warn!(%error, "the Admin API task failed"),
        Err(_) => {
            warn!("the Admin API did not finish its requests in time, closing them");
            task.abort();
        }
    }
}

/// Returns the dynamic settings of the newest saved version, or none before the first change.
async fn saved_dynamic(store: &Store) -> anyhow::Result<DynamicConfig> {
    Ok(match store.latest_version().await? {
        Some((version, dynamic)) => {
            info!(
                version = version.id,
                "using the saved configuration version"
            );
            dynamic
        }
        None => {
            info!("no configuration saved yet, starting without dynamic settings");
            DynamicConfig::default()
        }
    })
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
    next.set_dynamic(file.into_dynamic());
    match server.apply(next).await {
        Ok(snapshot) => info!(
            config_version = snapshot.version,
            listeners = server.listeners().await.len(),
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
