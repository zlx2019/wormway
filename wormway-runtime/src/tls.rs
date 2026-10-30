//! Certificates in effect: the TLS engine reports them, and the metrics show when they expire.

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
    /// End of the validity of its leaf certificate.
    pub not_after: SystemTime,
}
