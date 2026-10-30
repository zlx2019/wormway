//! TLS certificates: read from files, or got and renewed through ACME.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::HostPattern;

/// A TLS certificate: a chain and its private key read from PEM files, or one that Wormway gets
/// and renews through ACME. Set `cert` and `key`, or `acme`.
///
/// Relative paths are resolved against the directory of the configuration file. The files are
/// read again whenever the configuration is applied, so that replaced files take effect on
/// reload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    /// PEM file with the certificate chain, leaf certificate first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<PathBuf>,
    /// PEM file with the private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<PathBuf>,
    /// Get the certificate from the certificate authority of `[acme]` and renew it, in place
    /// of `cert` and `key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeCertificate>,
}

/// A certificate that Wormway gets through ACME.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AcmeCertificate {
    /// Host names the certificate covers, such as `example.com`. `*.example.com` covers one
    /// label in front of `example.com` and needs `dns-01`.
    pub domains: Vec<HostPattern>,
    /// How the certificate authority checks that the host names are ours.
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// The DNS provider that publishes the records of `dns-01`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsProvider>,
}

/// How the certificate authority checks that the host names of a certificate are ours.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AcmeChallenge {
    /// It fetches `http://<name>/.well-known/acme-challenge/<token>`, which every HTTP listener
    /// answers, so one must be reachable on port 80 for the names.
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// It looks up a TXT record at `_acme-challenge.<name>`, which `dns` publishes. Wildcard
    /// names need it.
    #[serde(rename = "dns-01")]
    Dns01,
}

/// A DNS provider whose API publishes the TXT records of `dns-01`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "provider", rename_all = "lowercase", deny_unknown_fields)]
pub enum DnsProvider {
    /// Cloudflare.
    Cloudflare {
        /// An API token that may edit the DNS records of the zones of the names (Zone, DNS,
        /// Edit).
        api_token: Secret,
    },
}

/// A secret that the configuration refers to instead of holding it, read whenever the
/// configuration is applied: `{ env = "NAME" }` takes an environment variable, `{ file =
/// "path" }` the content of a file, relative to the configuration file. Whitespace around the
/// value is dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Secret {
    /// The value of this environment variable.
    Env(String),
    /// The content of this file.
    File(PathBuf),
}
