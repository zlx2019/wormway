//! Secrets that the configuration refers to instead of holding them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

impl Secret {
    /// Reads the secret: the environment variable, or the file with a path relative to `base`,
    /// without the whitespace around the value. A missing or empty value is an error. It may
    /// read a file, so call it on the blocking pool.
    pub fn read(&self, base: &Path) -> Result<String, String> {
        let value = match self {
            Self::Env(name) => std::env::var(name)
                .map_err(|_| format!("environment variable {name} is not set"))?,
            Self::File(path) => {
                let path = base.join(path);
                std::fs::read_to_string(&path)
                    .map_err(|error| format!("cannot read {}: {error}", path.display()))?
            }
        };
        let value = value.trim();
        if value.is_empty() {
            return Err("the value is empty".to_owned());
        }
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Environment variables and files give their value without surrounding whitespace;
    /// missing ones and empty values are errors, with what was looked for.
    #[test]
    fn reads_secrets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "  secret-token\n").unwrap();
        std::fs::write(dir.path().join("empty"), "\n").unwrap();
        let file = |name: &str| Secret::File(name.into());
        assert_eq!(file("token").read(dir.path()).unwrap(), "secret-token");
        let absolute = Secret::File(dir.path().join("token"));
        assert_eq!(
            absolute.read(Path::new("/elsewhere")).unwrap(),
            "secret-token"
        );
        let empty = file("empty").read(dir.path()).unwrap_err();
        assert_eq!(empty, "the value is empty");
        let missing = file("missing").read(dir.path()).unwrap_err();
        assert!(missing.starts_with("cannot read "), "{missing}");

        let path = Secret::Env("PATH".to_owned());
        assert!(!path.read(dir.path()).unwrap().is_empty());
        let unset = Secret::Env("WORMWAY_TEST_SURELY_UNSET".to_owned());
        assert_eq!(
            unset.read(dir.path()).unwrap_err(),
            "environment variable WORMWAY_TEST_SURELY_UNSET is not set"
        );
    }
}
