//! Reading certificates: the chain and key from PEM files, checked against each other, and the
//! details of the leaf certificate.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls::{Error as TlsError, InconsistentKeys};
use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::extensions::GeneralName;
use zora_core::config::{Certificate, Issue, Name};

/// A certificate ready for handshakes, with its details.
#[derive(Debug)]
pub(crate) struct Loaded {
    /// The chain and the signing key, as rustls presents them.
    pub(crate) key: Arc<CertifiedKey>,
    /// Details of the leaf certificate.
    pub(crate) info: CertificateInfo,
}

impl Loaded {
    /// Returns the leaf certificate, to tell whether a certificate changed.
    pub(crate) fn leaf(&self) -> Option<&CertificateDer<'static>> {
        self.key.cert.first()
    }
}

/// Details of a certificate, read from its leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Host names the certificate covers, from its subject alternative names, in lowercase. A
    /// name such as `*.example.com` covers one label in front of `example.com`.
    pub names: Vec<String>,
    /// Distinguished name of the subject.
    pub subject: String,
    /// Distinguished name of the issuer.
    pub issuer: String,
    /// Start of the validity, in seconds since the Unix epoch.
    pub not_before: i64,
    /// End of the validity, in seconds since the Unix epoch.
    pub not_after: i64,
}

impl CertificateInfo {
    /// Reads the details of the leaf certificate `der`.
    fn parse(der: &CertificateDer<'_>) -> Result<Self, String> {
        let (_, leaf) = x509_parser::parse_x509_certificate(der)
            .map_err(|error| format!("invalid certificate: {error}"))?;
        let names = match leaf.subject_alternative_name() {
            Ok(Some(extension)) => extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
                    _ => None,
                })
                .collect(),
            Ok(None) => Vec::new(),
            Err(error) => return Err(format!("invalid subject alternative names: {error}")),
        };
        let validity = leaf.validity();
        Ok(Self {
            names,
            subject: leaf.subject().to_string(),
            issuer: leaf.issuer().to_string(),
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
        })
    }
}

/// Reads certificate `name` with the files of `certificate`, relative paths resolved against
/// `base`, and checks that the key belongs to the certificate. The problem comes back with the
/// path of the setting it concerns.
pub(crate) fn load(
    provider: &CryptoProvider,
    base: &Path,
    name: &Name,
    certificate: &Certificate,
) -> Result<Loaded, Issue> {
    let at = |field: &str| format!("certificates.{name}.{field}");
    let chain = read_chain(&base.join(&certificate.cert)).map_err(|e| Issue::new(at("cert"), e))?;
    let key = read_key(&base.join(&certificate.key)).map_err(|e| Issue::new(at("key"), e))?;
    let info = chain
        .first()
        .ok_or_else(|| "no certificate found".to_owned())
        .and_then(CertificateInfo::parse)
        .map_err(|e| Issue::new(at("cert"), e))?;
    let signing = provider
        .key_provider
        .load_private_key(key)
        .map_err(|error| Issue::new(at("key"), format!("unusable private key: {error}")))?;
    let key = CertifiedKey::new(chain, signing);
    match key.keys_match() {
        // Some keys cannot tell their public key; the handshake still works with them.
        Ok(()) | Err(TlsError::InconsistentKeys(InconsistentKeys::Unknown)) => {}
        Err(TlsError::InconsistentKeys(InconsistentKeys::KeyMismatch)) => {
            return Err(Issue::new(
                format!("certificates.{name}"),
                "the private key does not belong to the certificate",
            ));
        }
        Err(error) => {
            return Err(Issue::new(
                at("cert"),
                format!("unusable certificate: {error}"),
            ));
        }
    }
    Ok(Loaded {
        key: Arc::new(key),
        info,
    })
}

/// Reads the certificate chain in the PEM file at `path`.
fn read_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = read(path)?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    if chain.is_empty() {
        return Err(format!("no certificate found in {}", path.display()));
    }
    Ok(chain)
}

/// Reads the private key in the PEM file at `path`: PKCS #8, PKCS #1 (RSA) or SEC1 (EC).
fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let pem = read(path)?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|error| match error {
        pem::Error::NoItemsFound => format!("no private key found in {}", path.display()),
        error => format!("cannot parse {}: {error}", path.display()),
    })
}

/// Reads the file at `path`, with the path in the error.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::TempDir;

    use super::*;
    use crate::provider;

    /// Writes a self-signed certificate for `names` and its key into `dir` as `<file>.crt` and
    /// `<file>.key`, and returns the certificate setting for them.
    pub(crate) fn write_certificate(dir: &Path, file: &str, names: &[&str]) -> Certificate {
        let key = KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let cert = CertificateParams::new(names)
            .unwrap()
            .self_signed(&key)
            .unwrap();
        std::fs::write(dir.join(format!("{file}.crt")), cert.pem()).unwrap();
        std::fs::write(dir.join(format!("{file}.key")), key.serialize_pem()).unwrap();
        Certificate {
            cert: format!("{file}.crt").into(),
            key: format!("{file}.key").into(),
        }
    }

    /// Loads `certificate` from `dir` as certificate `site`.
    fn load_from(dir: &TempDir, certificate: &Certificate) -> Result<Loaded, Issue> {
        load(
            &provider(),
            dir.path(),
            &"site".parse().unwrap(),
            certificate,
        )
    }

    /// A certificate and its key are read, with the names and validity of the leaf.
    #[test]
    fn reads_certificates_and_their_details() {
        let dir = TempDir::new().unwrap();
        let certificate = write_certificate(dir.path(), "site", &["Example.com", "*.example.com"]);
        let loaded = load_from(&dir, &certificate).unwrap();
        assert_eq!(loaded.info.names, ["example.com", "*.example.com"]);
        assert!(loaded.info.not_before < loaded.info.not_after);
        assert_eq!(loaded.key.cert.len(), 1);

        // Absolute paths are used as they are.
        let absolute = Certificate {
            cert: dir.path().join("site.crt"),
            key: dir.path().join("site.key"),
        };
        let elsewhere = TempDir::new().unwrap();
        assert!(load_from(&elsewhere, &absolute).is_ok());
    }

    /// Missing and malformed files, and a key of another certificate, are reported at their
    /// setting.
    #[test]
    fn reports_unusable_files() {
        let dir = TempDir::new().unwrap();
        let site = write_certificate(dir.path(), "site", &["example.com"]);
        let other = write_certificate(dir.path(), "other", &["example.org"]);
        let issue = |certificate: Certificate| load_from(&dir, &certificate).unwrap_err();

        let missing = issue(Certificate {
            cert: "missing.crt".into(),
            ..site.clone()
        });
        assert_eq!(missing.path, "certificates.site.cert");
        assert!(missing.message.starts_with("cannot read"), "{missing}");

        let key_as_cert = issue(Certificate {
            cert: site.key.clone(),
            ..site.clone()
        });
        assert_eq!(key_as_cert.path, "certificates.site.cert");
        assert!(
            key_as_cert.message.starts_with("no certificate found"),
            "{key_as_cert}"
        );

        let cert_as_key = issue(Certificate {
            key: site.cert.clone(),
            ..site.clone()
        });
        assert_eq!(cert_as_key.path, "certificates.site.key");
        assert!(
            cert_as_key.message.starts_with("no private key found"),
            "{cert_as_key}"
        );

        let mismatch = issue(Certificate {
            key: other.key,
            ..site
        });
        assert_eq!(mismatch.path, "certificates.site");
        assert_eq!(
            mismatch.message,
            "the private key does not belong to the certificate"
        );
    }
}
