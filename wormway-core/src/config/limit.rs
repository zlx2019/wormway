//! Rate limits of routes: how many requests may come per period, counted by key.

use serde::{Deserialize, Serialize};

use super::{Duration, HeaderName};

/// A limit on the rate of the requests of a route, counted by key: each key may make `requests`
/// requests at once and gets them back evenly over `per`, so that on average it makes at most
/// `requests` requests per `per`. Requests over the limit are answered with 429 and a
/// `Retry-After` header. Each instance of Wormway counts on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Requests per period, which is also the most that may come at once.
    pub requests: u32,
    /// The period, such as `"1s"` or `"1m"`.
    pub per: Duration,
    /// What the requests are counted by. Default: `"client_ip"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<RateLimitKey>,
}

impl RateLimit {
    /// Returns what the requests are counted by.
    pub fn key(&self) -> RateLimitKey {
        self.key.clone().unwrap_or_default()
    }
}

/// What the requests of a rate limit are counted by.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// The IP address of the client.
    #[default]
    ClientIp,
    /// The value of a request header, such as `{ header = "X-Tenant" }`. Requests without the
    /// header count by the IP address of the client.
    Header(HeaderName),
    /// Nothing: the requests of the route count together.
    Route,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a rate limit from TOML.
    fn read(text: &str) -> Result<RateLimit, toml::de::Error> {
        toml::from_str(text)
    }

    /// Keys come as names or as a table for a header, counting by client IP address without
    /// one, and are written back in the form they were read.
    #[test]
    fn reads_and_writes_keys() {
        let plain = read("requests = 100\nper = \"1s\"\n").unwrap();
        assert_eq!(plain.requests, 100);
        assert_eq!(plain.per.get().as_secs(), 1);
        assert_eq!(plain.key(), RateLimitKey::ClientIp);
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"requests":100,"per":"1s"}"#
        );

        let route = read("requests = 5\nper = \"1m\"\nkey = \"route\"\n").unwrap();
        assert_eq!(route.key(), RateLimitKey::Route);
        let header = read("requests = 5\nper = \"1m\"\nkey = { header = \"X-Tenant\" }\n").unwrap();
        let RateLimitKey::Header(name) = header.key() else {
            panic!("expected a header key, got {:?}", header.key());
        };
        assert_eq!(name.as_str(), "X-Tenant");
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(
            json,
            r#"{"requests":5,"per":"1m","key":{"header":"X-Tenant"}}"#
        );
        assert_eq!(serde_json::from_str::<RateLimit>(&json).unwrap(), header);
    }

    /// Unknown keys, header names that are not tokens, and missing fields are rejected.
    #[test]
    fn rejects_malformed_limits() {
        for text in [
            "requests = 5\nper = \"1m\"\nkey = \"uri\"\n",
            "requests = 5\nper = \"1m\"\nkey = { header = \"X Tenant\" }\n",
            "requests = 5\nper = \"1m\"\nkey = { cookie = \"id\" }\n",
            "requests = 5\n",
            "per = \"1m\"\n",
            "requests = -1\nper = \"1m\"\n",
            "requests = 5\nper = \"1m\"\nburst = 10\n",
        ] {
            assert!(read(text).is_err(), "{text}");
        }
    }
}
