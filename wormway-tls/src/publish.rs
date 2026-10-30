//! Publishing the certificates that handshakes see: those of the configuration in effect, read
//! from files, together with those that ACME issued.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use wormway_core::config::{Listener, ListenerTls, Name};

use crate::load::Loaded;
use crate::resolve::TlsSnapshot;

/// The certificates and TLS listeners of one configuration.
#[derive(Debug, Default)]
pub(crate) struct ConfigCertificates {
    /// Certificates read from files, by name.
    pub(crate) files: BTreeMap<Name, Arc<Loaded>>,
    /// Names of the certificates that ACME issues.
    pub(crate) acme: BTreeSet<Name>,
    /// The TLS settings of each TLS listener.
    pub(crate) listeners: BTreeMap<Name, ListenerTls>,
}

impl ConfigCertificates {
    /// Takes the TLS settings of the TLS listeners among `listeners`.
    pub(crate) fn tls_listeners(
        listeners: &BTreeMap<Name, Listener>,
    ) -> BTreeMap<Name, ListenerTls> {
        listeners
            .iter()
            .filter_map(|(name, listener)| Some((name.clone(), listener.tls.clone()?)))
            .collect()
    }
}

/// What the handshakes see, and what it is built from.
#[derive(Debug, Default)]
pub(crate) struct Published {
    /// The certificates in effect and the index of every TLS listener.
    pub(crate) snapshot: ArcSwap<TlsSnapshot>,
    /// What the snapshot is built from. Publishing holds the lock, so that a change of the
    /// configuration and a certificate that ACME issued at the same time both stay.
    sources: Mutex<Sources>,
}

/// What a snapshot is built from.
#[derive(Debug, Default)]
struct Sources {
    /// The certificates and TLS listeners of the configuration in effect.
    config: Arc<ConfigCertificates>,
    /// Certificates that ACME issued, by name; presented while the configuration gets them
    /// through ACME.
    issued: BTreeMap<Name, Arc<Loaded>>,
}

impl Published {
    /// Publishes the certificates and TLS listeners of a configuration, with the issued
    /// certificates it gets through ACME, and returns the snapshot it replaces.
    pub(crate) fn set_config(&self, config: Arc<ConfigCertificates>) -> Arc<TlsSnapshot> {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        sources.config = config;
        self.publish(&sources)
    }

    /// Publishes `certificate` as the one that ACME issued for certificate `name`, or drops it
    /// with `None`.
    pub(crate) fn set_issued(&self, name: &Name, certificate: Option<Arc<Loaded>>) {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        match certificate {
            Some(certificate) => sources.issued.insert(name.clone(), certificate),
            None => sources.issued.remove(name),
        };
        self.publish(&sources);
    }

    /// Returns the certificate that ACME issued for certificate `name`, if any.
    pub(crate) fn issued(&self, name: &Name) -> Option<Arc<Loaded>> {
        let sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        sources.issued.get(name).cloned()
    }

    /// Builds the snapshot of `sources` and puts it in effect for new handshakes.
    fn publish(&self, sources: &Sources) -> Arc<TlsSnapshot> {
        let mut certificates = sources.config.files.clone();
        for name in &sources.config.acme {
            if let Some(issued) = sources.issued.get(name) {
                certificates.insert(name.clone(), issued.clone());
            }
        }
        let next = TlsSnapshot::new(certificates, &sources.config.listeners);
        self.snapshot.swap(Arc::new(next))
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use wormway_core::config::Config;

    use super::*;
    use crate::load::parse_issued;
    use crate::provider;

    /// A certificate for `name`, as ACME would issue it.
    fn issued(name: &str) -> Arc<Loaded> {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Arc::new(parse_issued(&provider(), &cert.pem(), &key.serialize_pem()).unwrap())
    }

    /// The certificates and TLS listeners of a file configuration with `text` added.
    fn config(text: &str) -> Arc<ConfigCertificates> {
        let config = Config::from_toml(&format!(
            "version = 1\n[config]\nsource = \"file\"\n[listeners.secure]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\ntls = {{ certificates = [\"site\"] }}\n{text}"
        ))
        .unwrap();
        Arc::new(ConfigCertificates {
            files: BTreeMap::new(),
            acme: config
                .certificates
                .iter()
                .filter(|(_, certificate)| certificate.acme.is_some())
                .map(|(name, _)| name.clone())
                .collect(),
            listeners: ConfigCertificates::tls_listeners(&config.listeners),
        })
    }

    /// Names of the certificates in effect.
    fn names(published: &Published) -> Vec<String> {
        let snapshot = published.snapshot.load();
        snapshot.certificates.keys().map(Name::to_string).collect()
    }

    /// An issued certificate is presented while the configuration gets it through ACME, also
    /// across changes of the configuration, and no longer once it is dropped.
    #[test]
    fn keeps_issued_certificates_across_changes() {
        let acme = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
        let site: Name = "site".parse().unwrap();
        let published = Published::default();
        published.set_config(config(acme));
        assert!(names(&published).is_empty());

        let certificate = issued("site.test");
        published.set_issued(&site, Some(certificate.clone()));
        assert_eq!(names(&published), ["site"]);
        let snapshot = published.snapshot.load();
        let presented = snapshot.find("secure", Some("site.test"));
        assert!(presented.is_some_and(|key| Arc::ptr_eq(&key, &certificate.key)));

        let other = "[listeners.other]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";
        published.set_config(config(&format!("{acme}{other}")));
        assert_eq!(names(&published), ["site"]);
        assert!(published.issued(&site).is_some());

        let files = "[certificates.site]\ncert = \"site.crt\"\nkey = \"site.key\"\n";
        published.set_config(config(files));
        assert!(names(&published).is_empty());
        published.set_config(config(acme));
        assert_eq!(names(&published), ["site"]);

        published.set_issued(&site, None);
        assert!(names(&published).is_empty());
        assert!(published.issued(&site).is_none());
    }
}
