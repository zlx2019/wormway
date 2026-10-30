//! Process signals.

/// What a signal asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// SIGHUP: reload the configuration and certificate files.
    Reload,
    /// SIGUSR1: open the access log file again, after a tool such as logrotate moved it.
    ReopenLogs,
    /// SIGINT or SIGTERM: shut down.
    Shutdown,
}

/// Receives SIGHUP, SIGUSR1, SIGINT and SIGTERM.
#[cfg(unix)]
pub struct Signals {
    /// SIGHUP.
    hangup: tokio::signal::unix::Signal,
    /// SIGUSR1.
    user1: tokio::signal::unix::Signal,
    /// SIGINT, sent by Ctrl-C.
    interrupt: tokio::signal::unix::Signal,
    /// SIGTERM.
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    /// Installs the handlers. Without them SIGHUP and SIGUSR1 would end the process.
    pub fn new() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            hangup: signal(SignalKind::hangup())?,
            user1: signal(SignalKind::user_defined1())?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Waits for the next signal.
    pub async fn next(&mut self) -> Signal {
        tokio::select! {
            _ = self.hangup.recv() => Signal::Reload,
            _ = self.user1.recv() => Signal::ReopenLogs,
            _ = self.interrupt.recv() => Signal::Shutdown,
            _ = self.terminate.recv() => Signal::Shutdown,
        }
    }
}

/// Receives Ctrl-C. Other platforms have no reload signal.
#[cfg(not(unix))]
pub struct Signals;

#[cfg(not(unix))]
impl Signals {
    /// Nothing to install up front.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self)
    }

    /// Waits for Ctrl-C. If it cannot be watched, waits forever rather than shutting down.
    pub async fn next(&mut self) -> Signal {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
        Signal::Shutdown
    }
}
