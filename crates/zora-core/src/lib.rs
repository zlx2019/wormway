//! Core types for zora: the configuration model, route and rule matching, error
//! types and more. It does not depend on any networking framework.
//!
//! This is currently a placeholder skeleton that lets the toolchain (formatting,
//! linting, tests and dependency auditing) run end to end.

/// Returns the version of this library, used by smoke tests and diagnostics.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version comes from Cargo.toml and must not be empty.
    #[test]
    fn version_is_not_empty() {
        assert!(!version().is_empty());
    }
}
