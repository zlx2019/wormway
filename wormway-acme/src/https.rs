//! The HTTPS connections of ACME and of the DNS provider APIs. They use the crypto of Wormway's
//! TLS, aws-lc-rs with post-quantum key exchange first, whatever the process-wide default of
//! rustls is, and check certificates the way of the system or against given authorities.

use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

/// Builds the connector of a client that checks certificates the way of the system, or
/// against `authorities` when given. It connects over plain HTTP too if `plain`, for test
/// servers.
pub(crate) fn connector(
    authorities: Option<Vec<CertificateDer<'static>>>,
    plain: bool,
) -> Result<HttpsConnector<HttpConnector>, String> {
    let provider = wormway_tls::provider();
    let builder = match authorities {
        None => HttpsConnectorBuilder::new()
            .with_provider_and_platform_verifier(provider)
            .map_err(|error| {
                format!("cannot use the certificate authorities of the system: {error}")
            })?,
        Some(authorities) => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(authorities);
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| format!("cannot set up TLS: {error}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpsConnectorBuilder::new().with_tls_config(config)
        }
    };
    let builder = if plain {
        builder.https_or_http()
    } else {
        builder.https_only()
    };
    Ok(builder.enable_http1().build())
}
