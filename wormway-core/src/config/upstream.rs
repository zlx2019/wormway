//! Upstreams: the servers that requests are balanced over.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{Duration, HeaderName};

/// A group of servers that requests are balanced over.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The servers. A server with weight 2 gets twice the share of one with weight 1.
    pub targets: Vec<Target>,
    /// How requests are spread over the targets. Default: `"round_robin"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<Balance>,
    /// What `consistent_hash` hashes. A request without it, such as one without the header,
    /// hashes its client IP address instead. Default: `"client_ip"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_key: Option<HashKey>,
    /// Time limits of the connections and requests to the targets.
    #[serde(default, skip_serializing_if = "Timeouts::is_default")]
    pub timeouts: Timeouts,
    /// How many other targets a request tries when it cannot connect, from 0 to
    /// [`Upstream::MAX_RETRIES`]. A request that reached a target is not sent to another one.
    /// Default: 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// The protocol spoken with the targets. Default: `"h1"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<UpstreamProtocol>,
    /// Connect to the targets with TLS. `tls = {}` checks their certificates against the
    /// system's certificate authorities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<UpstreamTls>,
}

impl Upstream {
    /// Default of `retries`.
    pub const DEFAULT_RETRIES: u32 = 1;
    /// Largest `retries`.
    pub const MAX_RETRIES: u32 = 10;

    /// Returns the balancing in effect.
    pub fn balance(&self) -> Balance {
        self.balance.unwrap_or_default()
    }

    /// Returns the key of `consistent_hash` in effect.
    pub fn hash_key(&self) -> HashKey {
        self.hash_key.clone().unwrap_or_default()
    }

    /// Returns the number of retries in effect.
    pub fn retries(&self) -> u32 {
        self.retries.unwrap_or(Self::DEFAULT_RETRIES)
    }

    /// Returns the protocol in effect.
    pub fn protocol(&self) -> UpstreamProtocol {
        self.protocol.unwrap_or_default()
    }
}

/// The protocol spoken with the targets of an upstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    /// HTTP/1.1.
    #[default]
    H1,
    /// HTTP/2 over TLS, agreed on during the handshake; needs `tls`. gRPC needs HTTP/2.
    H2,
    /// HTTP/2 without TLS, from the first byte (prior knowledge); not with `tls`.
    H2c,
}

/// TLS to the targets of an upstream. Relative paths are relative to the configuration file;
/// the files are read again on every change and on SIGHUP.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UpstreamTls {
    /// Name sent to the targets (SNI) and that their certificates must have. Default: the host
    /// name of the target, or its IP address, which is checked against the IP addresses of the
    /// certificate and not sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Check the certificates of the targets. `false` accepts any certificate, so that anyone
    /// on the path can read and change the traffic. Default: `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<bool>,
    /// PEM file with the certificate authorities that the certificates of the targets must come
    /// from, in place of the system's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<PathBuf>,
    /// PEM file with the certificate chain, leaf first, that Wormway presents to targets that ask
    /// for one. Set together with `key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    /// PEM file with the private key of `cert`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
}

impl UpstreamTls {
    /// Whether the certificates of the targets are checked.
    pub fn verify(&self) -> bool {
        self.verify.unwrap_or(true)
    }
}

/// How requests are spread over the targets of an upstream. Every way follows the weights.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    /// Each request goes to the next target in turn.
    #[default]
    RoundRobin,
    /// Each request goes to a target picked at random.
    Random,
    /// Each request goes to the target with the fewest requests in progress, relative to its
    /// weight.
    LeastConn,
    /// Requests with the same key, see `hash_key`, go to the same target, and adding or
    /// removing a target moves few keys.
    ConsistentHash,
}

/// What `consistent_hash` hashes: `"client_ip"`, `"uri"`, `{ header = "X-User" }` or
/// `{ cookie = "session" }`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HashKey {
    /// The IP address of the client.
    #[default]
    ClientIp,
    /// The path and the query of the request, as sent.
    Uri,
    /// The value of a request header.
    Header(HeaderName),
    /// The value of a cookie.
    Cookie(String),
}

/// Time limits of the connections and requests to the targets of an upstream. A request that
/// runs out of time is answered with 504.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    /// Time to connect to a target, TLS handshake included. Default: `"10s"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect: Option<Duration>,
    /// Longest wait for the next data from a target, such as the response header. Default:
    /// `"60s"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<Duration>,
    /// Longest wait for a target to take the next data of a request. Default: `"60s"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Duration>,
    /// How long an idle connection to a target is kept for the next request. Default: `"60s"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<Duration>,
}

impl Timeouts {
    /// Default of `connect`.
    pub const DEFAULT_CONNECT: Duration = Duration::from_secs(10);
    /// Default of `read`.
    pub const DEFAULT_READ: Duration = Duration::from_secs(60);
    /// Default of `write`.
    pub const DEFAULT_WRITE: Duration = Duration::from_secs(60);
    /// Default of `idle`.
    pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);

    /// Returns the connect timeout in effect.
    pub fn connect(&self) -> Duration {
        self.connect.unwrap_or(Self::DEFAULT_CONNECT)
    }

    /// Returns the read timeout in effect.
    pub fn read(&self) -> Duration {
        self.read.unwrap_or(Self::DEFAULT_READ)
    }

    /// Returns the write timeout in effect.
    pub fn write(&self) -> Duration {
        self.write.unwrap_or(Self::DEFAULT_WRITE)
    }

    /// Returns the idle timeout in effect.
    pub fn idle(&self) -> Duration {
        self.idle.unwrap_or(Self::DEFAULT_IDLE)
    }

    /// Whether every setting is left out.
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Time limits of a route, in place of those of its upstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RouteTimeouts {
    /// Longest wait for the next data from the upstream. Default: `read` of the upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<Duration>,
    /// Longest wait for the upstream to take the next data of a request. Default: `write` of
    /// the upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<Duration>,
}

impl RouteTimeouts {
    /// Whether every setting is left out.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// A server of an upstream. Written as its address, such as `"10.0.0.1:8080"` or
/// `"api.internal:8080"`, or as a table with a weight, such as
/// `{ address = "10.0.0.1:8080", weight = 2 }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Address of the server.
    pub address: TargetAddress,
    /// Share of the requests relative to the other targets, from 1 to [`Target::MAX_WEIGHT`].
    pub weight: u32,
}

impl Target {
    /// Weight of a target written as an address only.
    pub const DEFAULT_WEIGHT: u32 = 1;
    /// Largest weight. The load balancer keeps one slot per unit of weight, so the weight is
    /// bounded.
    pub const MAX_WEIGHT: u32 = 256;

    /// A target with the default weight.
    pub fn new(address: TargetAddress) -> Self {
        Self {
            address,
            weight: Self::DEFAULT_WEIGHT,
        }
    }
}

/// Where a target is: an IP address and a port, or a host name and a port. Host names are
/// resolved when the configuration is applied and every 30 seconds after; each of their
/// addresses becomes a target with the weight of the name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TargetAddress {
    /// An IP address and a port.
    Ip(SocketAddr),
    /// A host name, in lowercase, and a port.
    Name {
        /// The host name.
        host: String,
        /// The port.
        port: u16,
    },
}

impl From<SocketAddr> for TargetAddress {
    /// The address itself.
    fn from(address: SocketAddr) -> Self {
        Self::Ip(address)
    }
}

impl FromStr for TargetAddress {
    type Err = InvalidTargetAddress;

    /// Parses `ip:port`, `[ipv6]:port` or `host:port`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = text.parse() {
            return Ok(Self::Ip(address));
        }
        let invalid = || InvalidTargetAddress(text.to_owned());
        let (host, port) = text.rsplit_once(':').ok_or_else(invalid)?;
        let port = port.parse().map_err(|_| invalid())?;
        if !is_host_name(host) {
            return Err(invalid());
        }
        Ok(Self::Name {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl fmt::Display for TargetAddress {
    /// Writes the address in the form it is read.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(f),
            Self::Name { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl Serialize for TargetAddress {
    /// Writes the address as a string.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TargetAddress {
    /// Reads the address from a string.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// Whether `host` is a host name: dot-separated labels of 1 to 63 letters, digits, `-` and `_`,
/// not starting or ending with `-`, at most 253 characters in all, and not ending with a label of
/// digits only, which belongs to an IPv4 address.
pub(crate) fn is_host_name(host: &str) -> bool {
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    };
    host.len() <= 253
        && host.split('.').all(label_ok)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit()))
}

/// A target address that is neither an IP address with a port nor a host name with a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTargetAddress(String);

impl fmt::Display for InvalidTargetAddress {
    /// Shows the address and the forms that are expected.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid address {:?}, expected an IP address or a host name with a port, such as \
             \"10.0.0.1:8080\" or \"api.internal:8080\"",
            self.0
        )
    }
}

impl std::error::Error for InvalidTargetAddress {}

/// The table form of a target.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetTable {
    /// Address of the server.
    address: TargetAddress,
    /// Share of the requests.
    #[serde(default = "default_weight")]
    weight: u32,
}

/// Weight of a table without one.
fn default_weight() -> u32 {
    Target::DEFAULT_WEIGHT
}

impl Serialize for Target {
    /// Writes the address alone when the weight is the default, the table otherwise.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.weight == Self::DEFAULT_WEIGHT {
            self.address.serialize(serializer)
        } else {
            TargetTable {
                address: self.address.clone(),
                weight: self.weight,
            }
            .serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Target {
    /// Reads either form.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(TargetVisitor)
    }
}

/// Reads a target from a string or a table.
struct TargetVisitor;

impl<'de> Visitor<'de> for TargetVisitor {
    type Value = Target;

    /// Describes both forms for error messages.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an address such as \"10.0.0.1:8080\", or a table with address and weight")
    }

    /// The address form.
    fn visit_str<E: de::Error>(self, text: &str) -> Result<Target, E> {
        text.parse().map(Target::new).map_err(E::custom)
    }

    /// The table form.
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Target, A::Error> {
        let table = TargetTable::deserialize(MapAccessDeserializer::new(map))?;
        Ok(Target {
            address: table.address,
            weight: table.weight,
        })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Target {
    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Target".into()
    }

    /// Either form; keep the weight bounds in sync with `Target`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A server of an upstream: its address, such as \"10.0.0.1:8080\" or \"api.internal:8080\", or a table with a weight. Host names are resolved when the configuration is applied and every 30 seconds after.",
            "anyOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "properties": {
                        "address": {
                            "description": "Address of the server.",
                            "type": "string"
                        },
                        "weight": {
                            "description": "Share of the requests relative to the other targets.",
                            "type": "integer",
                            "minimum": 1,
                            "maximum": Target::MAX_WEIGHT,
                            "default": Target::DEFAULT_WEIGHT
                        }
                    },
                    "required": ["address"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the targets of a TOML upstream.
    fn targets(text: &str) -> Result<Vec<Target>, toml::de::Error> {
        toml::from_str::<Upstream>(text).map(|upstream| upstream.targets)
    }

    /// The target at `address` with the default weight.
    fn target(address: &str) -> Target {
        Target::new(address.parse().unwrap())
    }

    /// Both forms are read, and a table without a weight gets the default one.
    #[test]
    fn reads_both_forms() {
        let read = targets(
            r#"targets = ["10.0.0.1:80", { address = "[::1]:8080", weight = 3 }, { address = "10.0.0.2:80" }]"#,
        )
        .unwrap();
        assert_eq!(
            read,
            [
                target("10.0.0.1:80"),
                Target {
                    address: "[::1]:8080".parse().unwrap(),
                    weight: 3
                },
                target("10.0.0.2:80"),
            ]
        );
    }

    /// The default weight is written as the address alone, and both forms read back.
    #[test]
    fn writes_the_short_form_when_possible() {
        let upstream = Upstream {
            targets: vec![
                target("10.0.0.1:80"),
                Target {
                    address: "api.internal:80".parse().unwrap(),
                    weight: 2,
                },
            ],
            ..Upstream::default()
        };
        let json = serde_json::to_string(&upstream).unwrap();
        assert_eq!(
            json,
            r#"{"targets":["10.0.0.1:80",{"address":"api.internal:80","weight":2}]}"#
        );
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), upstream);
        let toml = toml::to_string(&upstream).unwrap();
        assert_eq!(toml::from_str::<Upstream>(&toml).unwrap(), upstream);
    }

    /// Host names are kept in lowercase with their port; anything else that is not an IP
    /// address is rejected.
    #[test]
    fn reads_host_names() {
        assert_eq!(
            "API.internal:8080".parse::<TargetAddress>(),
            Ok(TargetAddress::Name {
                host: "api.internal".to_owned(),
                port: 8080
            })
        );
        assert!("my_service:80".parse::<TargetAddress>().is_ok());
        for text in [
            "backend",
            "backend:",
            "backend:http",
            "backend:70000",
            "-backend:80",
            "back end:80",
            "a..b:80",
            "10.0.0.256:80",
            "::1:80",
            "[backend]:80",
            "http://backend:80",
        ] {
            assert!(text.parse::<TargetAddress>().is_err(), "{text}");
        }
    }

    /// Missing ports, unknown keys and other types are rejected with a message.
    #[test]
    fn rejects_malformed_targets() {
        let error = targets(r#"targets = ["backend"]"#).unwrap_err();
        assert!(
            error.message().starts_with("invalid address \"backend\""),
            "{error}"
        );
        assert!(targets(r#"targets = ["10.0.0.1"]"#).is_err());
        let error = targets(r#"targets = [{ address = "10.0.0.1", weight = 2 }]"#).unwrap_err();
        assert!(error.message().contains("invalid address"), "{error}");
        let error =
            targets(r#"targets = [{ address = "10.0.0.1:80", backup = true }]"#).unwrap_err();
        assert!(
            error.message().contains("unknown field `backup`"),
            "{error}"
        );
        let error = targets("targets = [80]").unwrap_err();
        assert!(error.message().contains("an address such as"), "{error}");
    }

    /// The protocol and the TLS settings are read and written back; an empty table turns TLS
    /// on with the defaults.
    #[test]
    fn reads_protocols_and_tls() {
        let text = r#"
            targets = ["10.0.0.1:443"]
            protocol = "h2"
            tls = { sni = "api.internal", ca = "certs/ca.pem", cert = "certs/wormway.crt", key = "certs/wormway.key" }
        "#;
        let upstream: Upstream = toml::from_str(text).unwrap();
        assert_eq!(upstream.protocol(), UpstreamProtocol::H2);
        let tls = upstream.tls.clone().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("api.internal"));
        assert!(tls.verify());
        assert_eq!(tls.ca, Some(PathBuf::from("certs/ca.pem")));
        let toml = toml::to_string(&upstream).unwrap();
        assert_eq!(toml::from_str::<Upstream>(&toml).unwrap(), upstream);

        let plain: Upstream = toml::from_str("targets = []\ntls = {}").unwrap();
        assert_eq!(plain.protocol(), UpstreamProtocol::H1);
        assert_eq!(plain.tls, Some(UpstreamTls::default()));
        assert!(toml::from_str::<Upstream>("targets = []\ntls = { crt = \"a\" }").is_err());
    }

    /// Balancing, the hash key, the time limits and the retries are read and written back.
    #[test]
    fn reads_and_writes_the_settings() {
        let text = r#"
            targets = ["10.0.0.1:80"]
            balance = "consistent_hash"
            hash_key = { cookie = "session" }
            timeouts = { connect = "2s", idle = "5m" }
            retries = 0
        "#;
        let upstream: Upstream = toml::from_str(text).unwrap();
        assert_eq!(upstream.balance(), Balance::ConsistentHash);
        assert_eq!(upstream.hash_key(), HashKey::Cookie("session".to_owned()));
        assert_eq!(upstream.timeouts.connect(), Duration::from_secs(2));
        assert_eq!(upstream.timeouts.read(), Timeouts::DEFAULT_READ);
        assert_eq!(upstream.timeouts.idle(), Duration::from_secs(300));
        assert_eq!(upstream.retries(), 0);
        let toml = toml::to_string(&upstream).unwrap();
        assert_eq!(toml::from_str::<Upstream>(&toml).unwrap(), upstream);
        let json = serde_json::to_string(&upstream).unwrap();
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), upstream);

        let plain: Upstream = toml::from_str(r#"targets = ["10.0.0.1:80"]"#).unwrap();
        assert_eq!(plain.balance(), Balance::RoundRobin);
        assert_eq!(plain.hash_key(), HashKey::ClientIp);
        assert_eq!(plain.retries(), Upstream::DEFAULT_RETRIES);
        assert_eq!(plain.timeouts, Timeouts::default());
        for key in [r#""uri""#, r#"{ header = "X-User" }"#, r#""client_ip""#] {
            let text = format!("targets = [\"10.0.0.1:80\"]\nhash_key = {key}");
            assert!(toml::from_str::<Upstream>(&text).is_ok(), "{key}");
        }
        assert!(toml::from_str::<Upstream>("targets = []\nbalance = \"fastest\"").is_err());
        assert!(toml::from_str::<Upstream>("targets = []\nprotocol = \"h3\"").is_err());
        assert!(toml::from_str::<Upstream>("targets = []\ntimeouts = { total = \"1s\" }").is_err());
    }
}
