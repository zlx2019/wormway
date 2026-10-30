//! Static settings: read from the configuration file at startup, a restart applies changes.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{Duration, TimeFormat};

/// Process settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Worker threads of the data plane. `0` starts one per CPU core.
    pub threads: usize,
    /// How long open connections may take to finish when Wormway shuts down or their listener is
    /// changed or removed. Connections still open after that are closed.
    pub shutdown_timeout: Duration,
}

impl Default for ServerSettings {
    /// One thread per CPU core, 30 seconds to shut down.
    fn default() -> Self {
        Self {
            threads: 0,
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// Logging.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct LogSettings {
    /// Log filter in `tracing` directive syntax, such as `"info"` or
    /// `"info,wormway_runtime=debug"`.
    pub level: String,
    /// Output format.
    pub format: LogFormat,
    /// How the logs write times, the access log included: a strftime pattern such as
    /// `"%Y-%m-%d %H:%M:%S%.3f"`. RFC 3339 when not set. The combined access log keeps the
    /// layout of Nginx and only takes the time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_format: Option<TimeFormat>,
    /// The time zone of the times in the logs.
    pub time_zone: TimeZone,
    /// The access log, one line per request. Off when not set; `[log.access]` turns it on with
    /// the defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessLogSettings>,
}

impl Default for LogSettings {
    /// `info` level as plain text with times in UTC, without access log.
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
            time_format: None,
            time_zone: TimeZone::Utc,
            access: None,
        }
    }
}

/// The time zone of the times in the logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum TimeZone {
    /// Coordinated Universal Time.
    #[default]
    Utc,
    /// The time zone of the system: the `TZ` environment variable, otherwise `/etc/localtime`.
    /// Changes to either take effect within a second.
    Local,
}

/// The access log. A thread of its own writes the lines, so requests never wait for it; lines
/// that it cannot keep up with are dropped and counted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct AccessLogSettings {
    /// Format of the lines. Default: `"json"`.
    pub format: AccessLogFormat,
    /// File that the lines are added to, relative to the configuration file; standard output
    /// when not set. SIGUSR1 opens it again, after a tool such as logrotate moved it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Format of the access log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum AccessLogFormat {
    /// One JSON object per line.
    #[default]
    Json,
    /// The combined log format of Nginx and Apache, which log analyzers read.
    Combined,
}

/// Log output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// The Admin API and the dashboard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct AdminSettings {
    /// Address of the Admin API and the dashboard.
    pub listen: SocketAddr,
    /// File holding the Admin API token, created with a random token on first start if missing.
    /// A relative path is resolved against `storage.data_dir`.
    pub token_file: PathBuf,
}

impl Default for AdminSettings {
    /// Loopback port 9872, token in `admin.token`.
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 9872)),
            token_file: PathBuf::from("admin.token"),
        }
    }
}

/// Where Wormway keeps its database and runtime state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct StorageSettings {
    /// Directory for the database and runtime state. A relative path is resolved against the
    /// directory of the configuration file.
    pub data_dir: PathBuf,
}

impl Default for StorageSettings {
    /// `data` next to the configuration file.
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
        }
    }
}

/// ACME, which gets and renews the certificates that set `acme`, from Let's Encrypt or another
/// certificate authority. Using it agrees to the terms of service of the authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct AcmeSettings {
    /// The directory of the certificate authority: `letsencrypt`, `letsencrypt-staging`, or
    /// the HTTPS URL of the directory of another one.
    pub directory: String,
    /// An address the certificate authority may write to about the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// PEM file with the certificate authorities that the HTTPS certificate of the directory
    /// is checked against, for private ACME servers; those of the system otherwise. Relative to
    /// the configuration file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
}

impl AcmeSettings {
    /// The directory of Let's Encrypt.
    pub const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
    /// The directory of the staging environment of Let's Encrypt, for tests.
    pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// Returns the URL of the directory.
    pub fn directory_url(&self) -> &str {
        match self.directory.as_str() {
            "letsencrypt" => Self::LETSENCRYPT,
            "letsencrypt-staging" => Self::LETSENCRYPT_STAGING,
            url => url,
        }
    }
}

impl Default for AcmeSettings {
    /// Let's Encrypt, without an email address.
    fn default() -> Self {
        Self {
            directory: "letsencrypt".to_owned(),
            email: None,
            ca: None,
        }
    }
}

/// Where the dynamic settings come from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct ConfigSettings {
    /// Source of the dynamic settings: listeners, certificates and the other entity tables.
    pub source: ConfigSource,
}

/// Source of the dynamic settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ConfigSource {
    /// The database. Changes go through the Admin API or the dashboard and are kept as versions.
    /// Dynamic settings in the configuration file are ignored.
    #[default]
    Db,
    /// The configuration file. Edit it and send SIGHUP to reload; the dashboard is read-only.
    File,
}
