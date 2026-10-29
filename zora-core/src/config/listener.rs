//! Listeners: the addresses that accept connections, and the protocol served on them.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::{Duration, Name};

/// A set of addresses served with one protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// Addresses to listen on, such as `["0.0.0.0:443"]`.
    pub listen: Vec<SocketAddr>,
    /// Protocol served on these addresses.
    pub protocol: Protocol,
    /// TLS termination. Without it the listener serves plain TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTls>,
    /// HTTP settings, for protocol `http`.
    #[serde(default, skip_serializing_if = "HttpSettings::is_default")]
    pub http: HttpSettings,
}

/// Protocol served by a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/1.1 and HTTP/2, served by the gateway.
    Http,
}

impl fmt::Display for Protocol {
    /// Writes the name used in the configuration file, such as `http`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
        })
    }
}

/// TLS settings of a listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ListenerTls {
    /// Names of the certificates the listener can present. The client's SNI picks one.
    pub certificates: Vec<Name>,
}

/// HTTP settings of a listener. Settings left out follow the defaults of the running zora.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HttpSettings {
    /// How long a kept-alive HTTP/1.1 connection, or an idle HTTP/2 connection, may wait for its
    /// next request before it is closed, rounded up to whole seconds. `"0s"` turns HTTP/1.1
    /// keep-alive off and closes idle HTTP/2 connections after one second. Default: `"75s"`, as
    /// in Nginx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout: Option<Duration>,
}

impl HttpSettings {
    /// Default of `keepalive_timeout`.
    pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);

    /// Returns the keep-alive timeout in effect.
    pub fn keepalive_timeout(&self) -> Duration {
        self.keepalive_timeout
            .unwrap_or(Self::DEFAULT_KEEPALIVE_TIMEOUT)
    }

    /// Whether every setting is left out.
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
