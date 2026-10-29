//! TLS to upstreams: the settings of an upstream read into what Pingora needs to connect to its
//! targets.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

use pingora::lb::Backend;
use pingora::protocols::tls::CaType;
use pingora::upstreams::peer::{HttpPeer, Scheme};
use pingora::utils::tls::{CertKey, WrappedX509, parse_x509};
use rustls::pki_types::CertificateDer;
use zora_core::config::{Issue, Name, UpstreamTls};
use zora_tls::Certificates;

use crate::upstream::TargetHost;

/// How the requests of one snapshot connect to the targets of an upstream with TLS.
pub(crate) struct PeerTls {
    /// Name that every target is sent and checked against, in place of its own.
    sni: Option<String>,
    /// Whether the certificates of the targets are checked.
    verify: bool,
    /// Authorities that the certificates of the targets must come from, in place of the
    /// system's.
    ca: Option<Arc<CaType>>,
    /// Certificate presented to targets that ask for one.
    client: Option<Arc<CertKey>>,
    /// Keeps connections made with different trust apart: Pingora's connection pool tells
    /// connections apart by address, name and client certificate serial, but not by authority.
    group_key: u64,
}

impl PeerTls {
    /// Reads the files of `settings`, the TLS settings of upstream `name`, with paths relative
    /// to the configuration file of `certificates`.
    pub(crate) async fn load(
        name: &Name,
        settings: &UpstreamTls,
        certificates: &Certificates,
    ) -> Result<Self, Vec<Issue>> {
        let at = format!("upstreams.{name}.tls");
        let (files, certificates) = (settings.clone(), certificates.clone());
        let read = tokio::task::spawn_blocking(move || {
            let ca = files
                .ca
                .as_ref()
                .map(|ca| certificates.read_authorities(ca, &format!("{at}.ca")))
                .transpose();
            let client = match (&files.cert, &files.key) {
                (Some(cert), Some(key)) => certificates
                    .read_client_certificate(cert, key, &at)
                    .map(Some),
                _ => Ok(None),
            };
            (ca, client)
        });
        let (ca, client) = read.await.map_err(|error| {
            vec![Issue::new(
                format!("upstreams.{name}.tls"),
                format!("cannot read the files: {error}"),
            )]
        })?;
        let issues: Vec<Issue> = [ca.as_ref().err(), client.as_ref().err()]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        let (Ok(ca), Ok(client)) = (ca, client) else {
            return Err(issues);
        };
        let group_key = group_key(ca.as_deref(), client.as_ref().map(|client| &*client.chain));
        Ok(Self {
            sni: settings.sni.clone(),
            verify: settings.verify(),
            ca: ca.map(|ca| authorities(&ca)),
            client: client.map(|client| {
                let chain = client.chain.iter().map(|cert| cert.to_vec()).collect();
                Arc::new(CertKey::new(chain, client.key.secret_der().to_vec()))
            }),
            group_key,
        })
    }

    /// Returns the name to send to `target` and check its certificate against: the configured
    /// one, the host name of the target, or its IP address, which rustls checks against the
    /// IP addresses of the certificate without sending it.
    pub(crate) fn sni(&self, target: &Backend) -> String {
        if let Some(sni) = &self.sni {
            return sni.clone();
        }
        if let Some(TargetHost(host)) = target.ext.get::<TargetHost>() {
            return host.to_string();
        }
        target
            .addr
            .as_inet()
            .map_or_else(String::new, |addr| addr.ip().to_string())
    }

    /// Sets TLS on `peer`, whose name is already set.
    pub(crate) fn configure(&self, peer: &mut HttpPeer) {
        peer.scheme = Scheme::HTTPS;
        peer.options.verify_cert = self.verify;
        peer.options.verify_hostname = self.verify;
        peer.options.ca = self.ca.clone();
        peer.client_cert_key = self.client.clone();
        peer.group_key = self.group_key;
    }
}

/// Returns the key that keeps connections made with authorities `ca` and client certificate
/// chain `client` apart from connections made with others. The two parts are hashed apart, so
/// that a certificate counts differently as an authority and as the client's.
fn group_key(ca: Option<&[CertificateDer<'_>]>, client: Option<&[CertificateDer<'_>]>) -> u64 {
    /// The bytes of each of `certificates`.
    fn bytes<'a>(certificates: &'a [CertificateDer<'_>]) -> Vec<&'a [u8]> {
        certificates
            .iter()
            .map(|certificate| certificate.as_ref())
            .collect()
    }
    let mut hasher = DefaultHasher::new();
    ca.map(bytes).hash(&mut hasher);
    client.map(bytes).hash(&mut hasher);
    hasher.finish()
}

/// Wraps `certificates`, checked to be X.509 when they were read, for Pingora.
fn authorities(certificates: &[CertificateDer<'static>]) -> Arc<CaType> {
    certificates
        .iter()
        .map(|certificate| WrappedX509::new(certificate.to_vec(), parse_x509))
        .collect::<Vec<_>>()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The certificate with bytes `bytes`.
    fn certificate(bytes: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(bytes.to_vec())
    }

    /// Group keys follow the authorities and the client certificate, each part on its own.
    #[test]
    fn keeps_trust_settings_apart() {
        let (a, b) = ([certificate(b"a")], [certificate(b"b")]);
        let both = [certificate(b"a"), certificate(b"b")];
        assert_eq!(group_key(Some(&a), None), group_key(Some(&a), None));
        assert_ne!(group_key(Some(&a), None), group_key(Some(&b), None));
        assert_ne!(group_key(Some(&a), None), group_key(None, Some(&a)));
        assert_ne!(group_key(Some(&a), Some(&b)), group_key(Some(&both), None));
        assert_ne!(group_key(None, None), group_key(Some(&a), None));
    }
}
