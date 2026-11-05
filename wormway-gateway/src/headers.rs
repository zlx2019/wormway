//! Header changes: the headers that tell upstreams about the client, the IDs of requests, and
//! the header rules of routes.

use std::cell::Cell;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::LazyLock;

use http::{HeaderName, HeaderValue};
use pingora::http::{CasedHeaderName, RequestHeader, ResponseHeader};
use rustls::crypto::SecureRandom;
use wormway_core::config::{self, HeaderRules};

/// The header rules of a route, parsed once for every request.
#[derive(Default)]
pub(crate) struct HeaderEdits {
    /// Headers to remove.
    remove: Vec<HeaderName>,
    /// Headers to set, replacing their values.
    set: Vec<(HeaderName, HeaderValue)>,
    /// Values to add.
    add: Vec<(HeaderName, HeaderValue)>,
}

impl HeaderEdits {
    /// Parses `rules`. They passed validation, so this fails only if the validation rules and
    /// the HTTP types disagree.
    pub(crate) fn new(rules: &HeaderRules) -> Result<Self, String> {
        let pairs =
            |values: &std::collections::BTreeMap<config::HeaderName, config::HeaderValue>| {
                values
                    .iter()
                    .map(|(name, value)| Ok((parse_name(name)?, parse_value(value)?)))
                    .collect::<Result<Vec<_>, String>>()
            };
        Ok(Self {
            remove: rules
                .remove
                .iter()
                .map(parse_name)
                .collect::<Result<_, _>>()?,
            set: pairs(&rules.set)?,
            add: pairs(&rules.add)?,
        })
    }

    /// How many headers the changes add at most.
    pub(crate) fn added(&self) -> usize {
        self.set.len() + self.add.len()
    }

    /// Makes the changes to `headers`: removes, then sets, then adds.
    pub(crate) fn apply(&self, headers: &mut impl EditHeaders) -> pingora::Result<()> {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.set {
            headers.insert(name, value.clone())?;
        }
        for (name, value) in &self.add {
            headers.append(name, value.clone())?;
        }
        Ok(())
    }
}

/// Parses a header name of the configuration.
fn parse_name(name: &config::HeaderName) -> Result<HeaderName, String> {
    HeaderName::from_bytes(name.as_str().as_bytes())
        .map_err(|error| format!("header name {name:?}: {error}"))
}

/// Parses a header value of the configuration.
fn parse_value(value: &config::HeaderValue) -> Result<HeaderValue, String> {
    HeaderValue::from_str(value.as_str())
        .map_err(|error| format!("header value {value:?}: {error}"))
}

/// The header changes that requests and responses share. Pingora keeps the case of header
/// names for HTTP/1.1, so changes go through it rather than through the header map.
pub(crate) trait EditHeaders {
    /// Removes every value of header `name`.
    fn remove(&mut self, name: &HeaderName);
    /// Replaces every value of header `name` with `value`.
    fn insert(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()>;
    /// Adds `value` after the values of header `name`.
    fn append(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()>;
}

impl EditHeaders for RequestHeader {
    /// Removes the header.
    fn remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }

    /// Replaces the header.
    fn insert(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()> {
        self.insert_header(name, value)
    }

    /// Adds a value.
    fn append(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()> {
        self.append_header(name, value).map(|_| ())
    }
}

impl EditHeaders for ResponseHeader {
    /// Removes the header.
    fn remove(&mut self, name: &HeaderName) {
        self.remove_header(name);
    }

    /// Replaces the header.
    fn insert(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()> {
        self.insert_header(name, value)
    }

    /// Adds a value.
    fn append(&mut self, name: &HeaderName, value: HeaderValue) -> pingora::Result<()> {
        self.append_header(name, value).map(|_| ())
    }
}

/// The headers that [`set_forwarded`] sets, parsed once rather than for every request.
static X_FORWARDED_FOR: CasedHeaderName =
    CasedHeaderName::from_static("x-forwarded-for", "X-Forwarded-For");
static X_REAL_IP: CasedHeaderName = CasedHeaderName::from_static("x-real-ip", "X-Real-IP");
static X_FORWARDED_PROTO: CasedHeaderName =
    CasedHeaderName::from_static("x-forwarded-proto", "X-Forwarded-Proto");
static X_FORWARDED_HOST: CasedHeaderName =
    CasedHeaderName::from_static("x-forwarded-host", "X-Forwarded-Host");
static X_CONSUMER: CasedHeaderName = CasedHeaderName::from_static("x-consumer", "X-Consumer");
static X_REQUEST_ID: CasedHeaderName = CasedHeaderName::from_static("x-request-id", "X-Request-Id");
/// How many headers [`set_forwarded`] adds at most.
pub(crate) const FORWARDED_HEADERS: usize = 6;

/// Sets the headers that tell the upstream about the client, replacing those the client sent,
/// which nothing vouches for: `X-Forwarded-For` and `X-Real-IP` with the address of `client`,
/// `X-Forwarded-Proto` with `https` if the listener has TLS, `X-Forwarded-Host` with the host
/// the client asked for, `X-Request-Id` with `id`, and `X-Consumer` with `consumer`, the consumer
/// that the authentication of the route found, if any.
pub(crate) fn set_forwarded(
    request: &mut RequestHeader,
    client: Option<IpAddr>,
    tls: bool,
    id: &RequestId,
    consumer: Option<&str>,
) -> pingora::Result<()> {
    match client {
        Some(ip) => {
            // A client of a dual-stack socket shows up as an IPv4-mapped IPv6 address.
            let ip = ip.to_canonical().to_string();
            request.insert_header(&X_FORWARDED_FOR, ip.as_str())?;
            request.insert_header(&X_REAL_IP, ip)?;
        }
        None => {
            request.remove_header(X_FORWARDED_FOR.name());
            request.remove_header(X_REAL_IP.name());
        }
    }
    let proto = if tls { "https" } else { "http" };
    request.insert_header(&X_FORWARDED_PROTO, HeaderValue::from_static(proto))?;
    // The Host header, or the authority of an HTTP/2 request that has none.
    let host = match request.headers.get(http::header::HOST) {
        Some(host) => Some(host.clone()),
        None => request
            .uri
            .authority()
            .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok()),
    };
    match host {
        Some(host) => request.insert_header(&X_FORWARDED_HOST, host)?,
        None => {
            request.remove_header(X_FORWARDED_HOST.name());
        }
    }
    match consumer {
        Some(consumer) => request.insert_header(&X_CONSUMER, consumer)?,
        None => {
            request.remove_header(X_CONSUMER.name());
        }
    }
    request.insert_header(&X_REQUEST_ID, id.as_str())
}

/// The ID of a request: 128 unpredictable bits in lowercase hex, like `$request_id` of Nginx.
pub(crate) struct RequestId([u8; 32]);

impl RequestId {
    /// Draws a new ID: a keyed hash of a counter of the thread, taken twice for 128 bits. The
    /// standard library draws the keys from the system once per thread, so that a request does
    /// not wait for a system call, as it would with the generator of aws-lc.
    pub(crate) fn new() -> Self {
        thread_local! {
            static KEYS: RandomState = RandomState::new();
            static COUNT: Cell<u64> = const { Cell::new(0) };
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let count = COUNT.with(|count| {
            let current = count.get();
            count.set(current.wrapping_add(1));
            current
        });
        let (high, low) =
            KEYS.with(|keys| (keys.hash_one((count, 0_u8)), keys.hash_one((count, 1_u8))));
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&high.to_le_bytes());
        bytes[8..].copy_from_slice(&low.to_le_bytes());
        let mut hex = [0; 32];
        let (pairs, _) = hex.as_chunks_mut::<2>();
        for (pair, byte) in pairs.iter_mut().zip(bytes) {
            *pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xF)]];
        }
        Self(hex)
    }

    /// Returns the ID as text.
    pub(crate) fn as_str(&self) -> &str {
        // Hex digits are always UTF-8.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

/// The random generator of aws-lc, through the crypto provider of rustls.
pub(crate) fn random() -> &'static dyn SecureRandom {
    static RANDOM: LazyLock<&'static dyn SecureRandom> =
        LazyLock::new(|| rustls::crypto::aws_lc_rs::default_provider().secure_random);
    *RANDOM
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a name or a value of the configuration.
    fn parse<T: std::str::FromStr<Err: std::fmt::Debug>>(text: &str) -> T {
        text.parse().unwrap()
    }

    /// Removes come first, then sets, then adds, and the other headers stay.
    #[test]
    fn edits_headers_in_order() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request.insert_header("X-Debug", "1").unwrap();
        request.insert_header("X-Env", "dev").unwrap();
        request.insert_header("X-Tag", "a").unwrap();
        request.insert_header("Accept", "*/*").unwrap();
        let rules = HeaderRules {
            remove: vec![parse("x-debug"), parse("X-Env")],
            set: [(parse("X-Env"), parse("prod"))].into(),
            add: [(parse("X-Tag"), parse("b"))].into(),
        };
        HeaderEdits::new(&rules)
            .unwrap()
            .apply(&mut request)
            .unwrap();
        let values = |name: &str| -> Vec<&str> {
            request
                .headers
                .get_all(name)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect()
        };
        assert!(values("x-debug").is_empty());
        assert_eq!(values("x-env"), ["prod"]);
        assert_eq!(values("x-tag"), ["a", "b"]);
        assert_eq!(values("accept"), ["*/*"]);
    }

    /// The forwarding headers replace those of the client, and the host comes from the Host
    /// header; the consumer replaces the one the client claims, or removes it.
    #[test]
    fn replaces_forwarding_headers() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request.insert_header("Host", "example.com:8080").unwrap();
        request.insert_header("X-Forwarded-For", "6.6.6.6").unwrap();
        request.insert_header("X-Real-IP", "6.6.6.6").unwrap();
        request.insert_header("X-Request-Id", "chosen").unwrap();
        request.insert_header("X-Consumer", "mallory").unwrap();
        let id = RequestId::new();
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        set_forwarded(&mut request, Some(mapped), true, &id, Some("alice")).unwrap();
        let value = |name: &str| request.headers[name].to_str().unwrap().to_owned();
        assert_eq!(value("x-forwarded-for"), "10.0.0.1");
        assert_eq!(value("x-real-ip"), "10.0.0.1");
        assert_eq!(value("x-forwarded-proto"), "https");
        assert_eq!(value("x-forwarded-host"), "example.com:8080");
        assert_eq!(value("x-request-id"), id.as_str());
        assert_eq!(value("x-consumer"), "alice");

        set_forwarded(&mut request, Some(mapped), true, &id, None).unwrap();
        assert!(!request.headers.contains_key("x-consumer"));
    }

    /// IDs are 32 lowercase hex digits and differ between requests.
    #[test]
    fn draws_request_ids() {
        let first = RequestId::new();
        let second = RequestId::new();
        assert_eq!(first.as_str().len(), 32);
        assert!(
            first
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(first.as_str(), second.as_str());
    }

    /// IDs do not repeat within a thread, nor between threads, whose keys differ.
    #[test]
    fn request_ids_do_not_repeat() {
        let draw = |count: usize| -> Vec<String> {
            (0..count)
                .map(|_| RequestId::new().as_str().to_owned())
                .collect()
        };
        let mut seen: std::collections::HashSet<String> = draw(100_000).into_iter().collect();
        assert_eq!(seen.len(), 100_000);
        let threads: Vec<_> = (0..4)
            .map(|_| std::thread::spawn(move || draw(20_000)))
            .collect();
        for thread in threads {
            seen.extend(thread.join().unwrap());
        }
        assert_eq!(seen.len(), 180_000);
    }
}
