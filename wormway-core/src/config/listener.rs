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
    /// Names of the certificates the listener can present. The host name the client sends (SNI)
    /// picks the certificate whose names cover it; when several do, the one listed first.
    pub certificates: Vec<Name>,
    /// What to do when the client sends a host name that no certificate covers, or none at all.
    /// Default: `"default"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_sni: Option<UnknownSni>,
}

impl ListenerTls {
    /// Returns the handling of unknown host names in effect.
    pub fn unknown_sni(&self) -> UnknownSni {
        self.unknown_sni.unwrap_or_default()
    }
}

/// Handling of a TLS handshake for a host name that no certificate of the listener covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum UnknownSni {
    /// Present the first certificate of the listener, as Nginx presents the certificate of its
    /// default server.
    #[default]
    Default,
    /// Fail the handshake, so that the certificates are not shown to clients that do not know a
    /// host name they cover, such as scanners connecting by IP address.
    Reject,
}

/// HTTP settings of a listener. Settings left out follow the defaults of the running Wormway.
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
    /// Accept HTTP/2 without TLS from clients that start with it (prior knowledge), next to
    /// HTTP/1.1. Only for listeners without TLS: those agree on HTTP/2 during the handshake
    /// (ALPN). Default: `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2c: Option<bool>,
}

impl HttpSettings {
    /// Default of `keepalive_timeout`.
    pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);

    /// Returns the keep-alive timeout in effect.
    pub fn keepalive_timeout(&self) -> Duration {
        self.keepalive_timeout
            .unwrap_or(Self::DEFAULT_KEEPALIVE_TIMEOUT)
    }

    /// Whether HTTP/2 without TLS is accepted.
    pub fn h2c(&self) -> bool {
        self.h2c.unwrap_or(false)
    }

    /// Whether every setting is left out.
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
