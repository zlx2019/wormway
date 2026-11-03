//! Certificates in effect: the TLS engine reports them, and the metrics show when they expire.
//! ACME reports how it is getting the certificates it manages, and renews them on request.

use std::time::SystemTime;

use wormway_core::config::Name;

/// Reports the certificates in effect.
pub trait TlsReport: Send + Sync + 'static {
    /// Returns every certificate in effect, in name order.
    fn certificates(&self) -> Vec<CertificateReport>;
}

/// A certificate in effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateReport {
    /// Name of the certificate.
    pub name: Name,
    /// Host names that its leaf certificate covers, in lowercase.
    pub names: Vec<String>,
    /// Distinguished name of the issuer of its leaf certificate.
    pub issuer: String,
    /// Start of the validity of its leaf certificate.
    pub not_before: SystemTime,
    /// End of the validity of its leaf certificate.
    pub not_after: SystemTime,
}

/// Reports the certificates that ACME gets and renews, and renews one on request.
pub trait AcmeReport: Send + Sync + 'static {
    /// Returns every certificate that ACME manages, in name order.
    fn certificates(&self) -> Vec<AcmeCertificateReport>;

    /// Orders certificate `name` again as soon as possible, without waiting for its renewal
    /// time or for the end of the wait after failures. Returns `false` if the configuration in
    /// effect does not get `name` through ACME.
    fn renew(&self, name: &Name) -> bool;
}

/// How ACME is doing with one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeCertificateReport {
    /// Name of the certificate.
    pub name: Name,
    /// When the certificate in effect is renewed; `None` before one was issued.
    pub renew_at: Option<SystemTime>,
    /// When the next order is placed after the last one failed; `None` without failures.
    pub retry_at: Option<SystemTime>,
    /// Whether an order is in progress.
    pub ordering: bool,
    /// Orders that failed in a row.
    pub failures: u32,
    /// Why the last order failed.
    pub last_error: Option<String>,
}
