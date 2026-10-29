//! Picking the certificate of a handshake: the certificates of one configuration, indexed by the
//! host names they cover for every TLS listener.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use zora_core::config::{Listener, Name, UnknownSni};

use crate::load::Loaded;

/// The certificates of one configuration and the index of every TLS listener. It never changes:
/// a new configuration builds a new snapshot.
#[derive(Debug, Default)]
pub(crate) struct TlsSnapshot {
    /// Certificates by name.
    pub(crate) certificates: BTreeMap<Name, Arc<Loaded>>,
    /// Index of each TLS listener.
    listeners: HashMap<Name, SniIndex>,
}

impl TlsSnapshot {
    /// Indexes `certificates` for every TLS listener of `listeners`.
    pub(crate) fn new(
        certificates: BTreeMap<Name, Arc<Loaded>>,
        listeners: &BTreeMap<Name, Listener>,
    ) -> Self {
        let listeners = listeners
            .iter()
            .filter_map(|(name, listener)| {
                let tls = listener.tls.as_ref()?;
                // Validation made sure that every certificate a listener names exists.
                let own = tls
                    .certificates
                    .iter()
                    .filter_map(|certificate| certificates.get(certificate));
                let index = SniIndex::new(own.map(Arc::as_ref), tls.unknown_sni());
                Some((name.clone(), index))
            })
            .collect();
        Self {
            certificates,
            listeners,
        }
    }
}

/// The certificates one listener can present, by the host names they cover.
#[derive(Debug, Default)]
struct SniIndex {
    /// Certificates by exact host name.
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Certificates for one label in front of a name, keyed by the name: `example.com` for
    /// `*.example.com`.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    /// Certificate for clients that send another host name or none, if any.
    fallback: Option<Arc<CertifiedKey>>,
}

impl SniIndex {
    /// Indexes `certificates` in the order of the listener: when two cover the same name, the
    /// first one wins, and it is also the fallback unless unknown names are rejected.
    fn new<'a>(certificates: impl IntoIterator<Item = &'a Loaded>, unknown: UnknownSni) -> Self {
        let mut index = Self::default();
        for loaded in certificates {
            for name in &loaded.info.names {
                let map = match name.strip_prefix("*.") {
                    Some(parent) => index.wildcard.entry(parent.to_owned()),
                    None => index.exact.entry(name.clone()),
                };
                map.or_insert_with(|| loaded.key.clone());
            }
            if index.fallback.is_none() && unknown == UnknownSni::Default {
                index.fallback = Some(loaded.key.clone());
            }
        }
        index
    }

    /// Returns the certificate for host name `sni`, which rustls gives in lowercase, or for a
    /// client that sends none.
    fn find(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let covered = sni.and_then(|name| {
            self.exact.get(name).or_else(|| {
                let (_, parent) = name.split_once('.')?;
                self.wildcard.get(parent)
            })
        });
        covered.or(self.fallback.as_ref()).cloned()
    }
}

/// Picks the certificate of each handshake on one listener from the certificates in effect.
#[derive(Debug)]
pub(crate) struct ListenerResolver {
    /// The listener.
    listener: Name,
    /// The certificates in effect.
    snapshot: Arc<ArcSwap<TlsSnapshot>>,
}

impl ListenerResolver {
    /// Creates the resolver of `listener`.
    pub(crate) fn new(listener: Name, snapshot: Arc<ArcSwap<TlsSnapshot>>) -> Self {
        Self { listener, snapshot }
    }
}

impl ResolvesServerCert for ListenerResolver {
    /// Returns the certificate for the host name of the handshake. `None` fails the handshake.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.snapshot
            .load()
            .listeners
            .get(&self.listener)?
            .find(client_hello.server_name())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;
    use zora_core::config::Config;

    use super::*;
    use crate::load::{load, tests::write_certificate};
    use crate::provider;

    /// Certificates `a` (`a.test`, `www.a.test`), `wild` (`*.b.test`) and `other` (`a.test`,
    /// `c.test`), and listeners that use them: `default` presents `a` to unknown names, `strict`
    /// rejects them.
    fn snapshot(dir: &TempDir) -> TlsSnapshot {
        let config = Config::from_toml(
            r#"
            version = 1
            [listeners.default]
            listen = ["127.0.0.1:0"]
            protocol = "http"
            tls = { certificates = ["a", "wild", "other"] }
            [listeners.strict]
            listen = ["127.0.0.1:0"]
            protocol = "http"
            tls = { certificates = ["wild"], unknown_sni = "reject" }
            [listeners.plain]
            listen = ["127.0.0.1:0"]
            protocol = "http"
            [certificates.a]
            cert = "a.crt"
            key = "a.key"
            [certificates.wild]
            cert = "wild.crt"
            key = "wild.key"
            [certificates.other]
            cert = "other.crt"
            key = "other.key"
            "#,
        )
        .unwrap();
        for (file, names) in [
            ("a", &["a.test", "www.a.test"][..]),
            ("wild", &["*.b.test"]),
            ("other", &["a.test", "c.test"]),
        ] {
            write_certificate(dir.path(), file, names);
        }
        let certificates = config
            .certificates
            .iter()
            .map(|(name, certificate)| {
                let loaded = load(&provider(), dir.path(), name, certificate).unwrap();
                (name.clone(), Arc::new(loaded))
            })
            .collect();
        TlsSnapshot::new(certificates, &config.listeners)
    }

    /// Name of the certificate that `listener` presents for `sni`.
    fn presented(snapshot: &TlsSnapshot, listener: &str, sni: Option<&str>) -> Option<String> {
        let key = snapshot.listeners.get(listener)?.find(sni)?;
        snapshot
            .certificates
            .iter()
            .find(|(_, loaded)| Arc::ptr_eq(&loaded.key, &key))
            .map(|(name, _)| name.to_string())
    }

    /// Exact names, one label under a wildcard, the first certificate for a shared name, and the
    /// first certificate for unknown names or none.
    #[test]
    fn picks_certificates_by_host_name() {
        let dir = TempDir::new().unwrap();
        let snapshot = snapshot(&dir);
        let pick = |sni| presented(&snapshot, "default", sni);
        assert_eq!(pick(Some("www.a.test")).as_deref(), Some("a"));
        assert_eq!(pick(Some("x.b.test")).as_deref(), Some("wild"));
        assert_eq!(pick(Some("a.test")).as_deref(), Some("a"));
        assert_eq!(pick(Some("c.test")).as_deref(), Some("other"));
        assert_eq!(pick(Some("y.x.b.test")).as_deref(), Some("a"));
        assert_eq!(pick(Some("b.test")).as_deref(), Some("a"));
        assert_eq!(pick(None).as_deref(), Some("a"));
    }

    /// A listener that rejects unknown names presents only its own certificates, for the names
    /// they cover; listeners without TLS have no index.
    #[test]
    fn rejects_unknown_names_when_asked() {
        let dir = TempDir::new().unwrap();
        let snapshot = snapshot(&dir);
        let pick = |sni| presented(&snapshot, "strict", sni);
        assert_eq!(pick(Some("x.b.test")).as_deref(), Some("wild"));
        assert_eq!(pick(Some("a.test")), None);
        assert_eq!(pick(None), None);
        assert!(!snapshot.listeners.contains_key("plain"));
    }
}
