//! Reading the secrets that the configuration refers to.

use std::path::Path;

use wormway_core::config::Secret;

/// Reads `secret`: the environment variable, or the file with a path relative to `base`,
/// without the whitespace around the value. A missing or empty value is an error.
pub(crate) async fn read(secret: &Secret, base: &Path) -> Result<String, String> {
    let value = match secret {
        Secret::Env(name) => {
            std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))?
        }
        Secret::File(path) => {
            let path = base.join(path);
            tokio::fs::read_to_string(&path)
                .await
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?
        }
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("the value is empty".to_owned());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Environment variables and files give their value without surrounding whitespace;
    /// missing ones and empty values are errors, with what was looked for.
    #[tokio::test]
    async fn reads_secrets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "  secret-token\n").unwrap();
        std::fs::write(dir.path().join("empty"), "\n").unwrap();
        let file = |name: &str| Secret::File(name.into());
        assert_eq!(
            read(&file("token"), dir.path()).await.unwrap(),
            "secret-token"
        );
        let absolute = Secret::File(dir.path().join("token"));
        assert_eq!(
            read(&absolute, Path::new("/elsewhere")).await.unwrap(),
            "secret-token"
        );
        let empty = read(&file("empty"), dir.path()).await.unwrap_err();
        assert_eq!(empty, "the value is empty");
        let missing = read(&file("missing"), dir.path()).await.unwrap_err();
        assert!(missing.starts_with("cannot read "), "{missing}");

        assert!(
            !read(&Secret::Env("PATH".to_owned()), dir.path())
                .await
                .unwrap()
                .is_empty()
        );
        let unset = Secret::Env("WORMWAY_TEST_SURELY_UNSET".to_owned());
        assert_eq!(
            read(&unset, dir.path()).await.unwrap_err(),
            "environment variable WORMWAY_TEST_SURELY_UNSET is not set"
        );
    }
}
