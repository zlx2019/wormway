//! Listeners: the addresses that accept connections, and the protocol served on them.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::Name;

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
    pub tls: Option<ListenerTls>,
}

/// Protocol served by a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/1.1 and HTTP/2, served by the gateway.
    Http,
}

/// TLS settings of a listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ListenerTls {
    /// Names of the certificates the listener can present. The client's SNI picks one.
    pub certificates: Vec<Name>,
}
