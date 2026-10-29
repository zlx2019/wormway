//! Upstreams: the servers that requests are balanced over.

use std::fmt;
use std::net::SocketAddr;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A group of servers that requests are balanced over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The servers. Each request goes to the next one in turn, and a server with weight 2 gets
    /// twice the share of one with weight 1.
    pub targets: Vec<Target>,
}

/// A server of an upstream. Written as its address, such as `"10.0.0.1:8080"`, or as a table
/// with a weight, such as `{ address = "10.0.0.1:8080", weight = 2 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// Address of the server.
    pub address: SocketAddr,
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
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            weight: Self::DEFAULT_WEIGHT,
        }
    }
}

/// The table form of a target.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetTable {
    /// Address of the server.
    address: SocketAddr,
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
            serializer.collect_str(&self.address)
        } else {
            TargetTable {
                address: self.address,
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
        text.parse().map(Target::new).map_err(|_| {
            E::custom(format!(
                "invalid address {text:?}, expected an IP address and a port such as \"10.0.0.1:8080\""
            ))
        })
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
            "description": "A server of an upstream: its address, such as \"10.0.0.1:8080\", or a table with a weight.",
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
                Target::new("10.0.0.1:80".parse().unwrap()),
                Target {
                    address: "[::1]:8080".parse().unwrap(),
                    weight: 3
                },
                Target::new("10.0.0.2:80".parse().unwrap()),
            ]
        );
    }

    /// The default weight is written as the address alone, and both forms read back.
    #[test]
    fn writes_the_short_form_when_possible() {
        let upstream = Upstream {
            targets: vec![
                Target::new("10.0.0.1:80".parse().unwrap()),
                Target {
                    address: "10.0.0.2:80".parse().unwrap(),
                    weight: 2,
                },
            ],
        };
        let json = serde_json::to_string(&upstream).unwrap();
        assert_eq!(
            json,
            r#"{"targets":["10.0.0.1:80",{"address":"10.0.0.2:80","weight":2}]}"#
        );
        assert_eq!(serde_json::from_str::<Upstream>(&json).unwrap(), upstream);
        let toml = toml::to_string(&upstream).unwrap();
        assert_eq!(toml::from_str::<Upstream>(&toml).unwrap(), upstream);
    }

    /// Host names, missing ports, unknown keys and other types are rejected with a message.
    #[test]
    fn rejects_malformed_targets() {
        let error = targets(r#"targets = ["backend:80"]"#).unwrap_err();
        assert!(
            error
                .message()
                .starts_with("invalid address \"backend:80\""),
            "{error}"
        );
        assert!(targets(r#"targets = ["10.0.0.1"]"#).is_err());
        let error =
            targets(r#"targets = [{ address = "10.0.0.1:80", backup = true }]"#).unwrap_err();
        assert!(
            error.message().contains("unknown field `backup`"),
            "{error}"
        );
        let error = targets("targets = [80]").unwrap_err();
        assert!(error.message().contains("an address such as"), "{error}");
    }
}
