//! TLS certificates.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A certificate chain and its private key, read from PEM files. Relative paths are resolved
/// against the directory of the configuration file. The files are read again whenever the
/// configuration is applied, so that replaced files take effect on reload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    /// PEM file with the certificate chain, leaf certificate first.
    pub cert: PathBuf,
    /// PEM file with the private key.
    pub key: PathBuf,
}
