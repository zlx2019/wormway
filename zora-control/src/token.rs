//! The Admin API token.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use subtle::ConstantTimeEq;

/// The secret that Admin API requests present as `Authorization: Bearer <token>`.
#[derive(Clone)]
pub struct AdminToken(Arc<str>);

impl AdminToken {
    /// Uses `token` without surrounding whitespace. An empty token is refused.
    pub fn new(token: &str) -> Result<Self, TokenError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(TokenError::Empty);
        }
        Ok(Self(token.into()))
    }

    /// Reads the token from the file at `path`. If the file does not exist, creates it with a
    /// new random token that only its owner can read. Also returns whether it was created.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), TokenError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok((Self::new(&text)?, false)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let token = random_hex(32).map_err(TokenError::Random)?;
                write_private(path, &format!("{token}\n")).map_err(TokenError::Io)?;
                Ok((Self(token.into()), true))
            }
            Err(error) => Err(TokenError::Io(error)),
        }
    }

    /// Whether `presented` is the token. The comparison takes as long wherever the first
    /// difference is, so timing does not reveal the token.
    pub fn matches(&self, presented: &str) -> bool {
        self.0.as_bytes().ct_eq(presented.as_bytes()).into()
    }
}

impl fmt::Debug for AdminToken {
    /// Never shows the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminToken(..)")
    }
}

/// Why no token is available.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The token, or the file holding it, is empty.
    #[error("the Admin API token is empty")]
    Empty,
    /// The token file could not be read or written.
    #[error("cannot read or write the token file")]
    Io(#[source] io::Error),
    /// No random token could be generated.
    #[error("cannot generate a token")]
    Random(#[source] getrandom::Error),
}

/// Creates the file at `path` with `content`, readable and writable by its owner only. Fails if
/// the file exists.
fn write_private(path: &Path, content: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(content.as_bytes())
}

/// Returns `bytes` random bytes from the operating system, as lowercase hex.
pub(crate) fn random_hex(bytes: usize) -> Result<String, getrandom::Error> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the exact token matches; surrounding whitespace in the source is ignored.
    #[test]
    fn matches_exactly() {
        let token = AdminToken::new(" secret\n").unwrap();
        assert!(token.matches("secret"));
        for wrong in ["", "secre", "secret ", "Secret", "secrets"] {
            assert!(!token.matches(wrong), "{wrong:?}");
        }
        assert!(matches!(AdminToken::new(" \n"), Err(TokenError::Empty)));
    }

    /// The token is never printed.
    #[test]
    fn debug_hides_the_token() {
        assert_eq!(
            format!("{:?}", AdminToken::new("secret").unwrap()),
            "AdminToken(..)"
        );
    }

    /// A missing file is created once with a private random token, then read back.
    #[test]
    fn creates_the_token_file_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.token");
        let (created, was_created) = AdminToken::load_or_create(&path).unwrap();
        assert!(was_created);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), 64);
        assert!(created.matches(text.trim()));

        let (loaded, was_created) = AdminToken::load_or_create(&path).unwrap();
        assert!(!was_created);
        assert!(loaded.matches(text.trim()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
