//! The configuration model: the types behind `zora.toml`, parsing and validation.
//!
//! Static settings (`server`, `log`, `admin`, `storage` and `config`) are read once at startup.
//! Dynamic settings (`listeners`, `certificates` and the entity tables added later) come from
//! the database or from this file, as chosen by `config.source`, and can change while running.
//!
//! [`Config::from_toml`] loads a configuration in two stages. Parsing checks the syntax and the
//! structure and stops at the first error, which carries a line and column. Validation checks
//! the rules that span fields and reports every problem, each with the path of its setting.

mod certificate;
mod duration;
mod error;
mod listener;
mod name;
mod settings;
mod validate;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use certificate::Certificate;
pub use duration::{Duration, ParseDurationError};
pub use error::{ConfigError, Issue, ParseError, Position};
pub use listener::{Listener, ListenerTls, Protocol};
pub use name::{InvalidName, Name};
pub use settings::{
    AdminSettings, ConfigSettings, ConfigSource, LogFormat, LogSettings, ServerSettings,
    StorageSettings,
};

/// The configuration file, `zora.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(title = "zora configuration"))]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Version of the configuration format. This build reads version 1.
    pub version: Version,
    /// Process settings. Static: a restart applies changes.
    #[serde(default)]
    pub server: ServerSettings,
    /// Logging. Static: a restart applies changes.
    #[serde(default)]
    pub log: LogSettings,
    /// The Admin API and the dashboard. Static: a restart applies changes.
    #[serde(default)]
    pub admin: AdminSettings,
    /// Where zora keeps its database and runtime state. Static: a restart applies changes.
    #[serde(default)]
    pub storage: StorageSettings,
    /// Where the dynamic settings come from. Static: a restart applies changes.
    #[serde(default)]
    pub config: ConfigSettings,
    /// Listeners by name. Dynamic: read from this file only when `config.source` is `"file"`.
    #[serde(default)]
    pub listeners: BTreeMap<Name, Listener>,
    /// TLS certificates by name. Dynamic: read from this file only when `config.source` is
    /// `"file"`.
    #[serde(default)]
    pub certificates: BTreeMap<Name, Certificate>,
}

impl Config {
    /// Parses TOML text and validates the result.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        // Check the version first. Tables are deserialized in key order rather than file order,
        // so in one pass an unknown key could hide the version error of a newer file.
        toml::from_str::<Header>(text).map_err(|e| ParseError::from_toml(&e, text))?;
        let config: Self = toml::from_str(text).map_err(|e| ParseError::from_toml(&e, text))?;
        config.validate().map_err(ConfigError::Invalid)?;
        Ok(config)
    }

    /// Checks the rules that span fields, such as references between entities and address
    /// conflicts, and returns every problem found.
    pub fn validate(&self) -> Result<(), Vec<Issue>> {
        let issues = validate::errors(self);
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    /// Returns settings that are accepted but have no effect, such as dynamic settings in the
    /// file while `config.source` is `"db"`.
    pub fn warnings(&self) -> Vec<Issue> {
        validate::warnings(self)
    }
}

/// The part of the file read before everything else; other keys are ignored here.
#[derive(Deserialize)]
struct Header {
    /// Checked on its own so that it is the first error reported.
    #[expect(dead_code, reason = "only deserialized for the version check")]
    version: Version,
}

/// Version of the configuration format.
///
/// Parsing rejects every version other than [`Version::CURRENT`], so a file written for another
/// format fails up front instead of being misread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Version(u32);

impl Version {
    /// The version this build reads.
    pub const CURRENT: Self = Self(1);
}

impl TryFrom<u32> for Version {
    type Error = UnsupportedVersion;

    /// Accepts the current version only.
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Self::CURRENT.0 {
            Ok(Self(value))
        } else {
            Err(UnsupportedVersion(value))
        }
    }
}

impl From<Version> for u32 {
    /// Returns the version number.
    fn from(version: Version) -> Self {
        version.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Version {
    /// Inlined: a named definition would add nothing to a single constant.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Version".into()
    }

    /// The current version as the only valid value.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "integer", "const": Version::CURRENT.0 })
    }
}

/// Error for a configuration format version this build cannot read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unsupported configuration version {0}, this build reads version {current}", current = Version::CURRENT.0)]
pub struct UnsupportedVersion(pub u32);

/// Returns the JSON Schema of the configuration file as pretty-printed JSON. Editors use it for
/// completion and validation, and `zora schema` prints it.
#[cfg(feature = "schema")]
pub fn json_schema() -> String {
    let schema = schemars::generate::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<Config>();
    // `{:#}` pretty-prints a JSON value, the same output as `serde_json::to_string_pretty`.
    format!("{:#}", schema.as_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `text` and returns the parse error it must produce.
    fn parse_error(text: &str) -> ParseError {
        match Config::from_toml(text) {
            Err(ConfigError::Parse(error)) => error,
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    /// Shorthand for a position.
    fn at(line: usize, column: usize) -> Option<Position> {
        Some(Position { line, column })
    }

    /// A file with only the version gets every default.
    #[test]
    fn minimal_file_uses_defaults() {
        let config = Config::from_toml("version = 1").unwrap();
        assert_eq!(config.server.threads, 0);
        assert_eq!(
            config.server.shutdown_timeout.get(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(config.log.format, LogFormat::Text);
        assert_eq!(config.admin.listen, "127.0.0.1:9090".parse().unwrap());
        assert_eq!(config.config.source, ConfigSource::Db);
        assert!(config.listeners.is_empty() && config.certificates.is_empty());
    }

    /// Every setting can be written out, and the entity tables are keyed by name.
    #[test]
    fn parses_full_file() {
        let config = Config::from_toml(
            r#"
            version = 1
            [server]
            threads = 4
            shutdown_timeout = "1m30s"
            [log]
            level = "debug"
            format = "json"
            [admin]
            listen = "[::1]:9443"
            token_file = "/run/secrets/zora"
            [storage]
            data_dir = "/var/lib/zora"
            [config]
            source = "file"
            [listeners.websecure]
            listen = ["0.0.0.0:443", "[::]:443"]
            protocol = "http"
            tls = { certificates = ["example"] }
            [certificates.example]
            cert = "example.crt"
            key = "example.key"
            "#,
        )
        .unwrap();
        assert_eq!(config.server.shutdown_timeout.get().as_secs(), 90);
        assert_eq!(config.config.source, ConfigSource::File);
        let listener = &config.listeners["websecure"];
        assert_eq!(listener.listen.len(), 2);
        assert_eq!(
            listener.tls.as_ref().unwrap().certificates[0].as_str(),
            "example"
        );
        assert!(config.warnings().is_empty());
    }

    /// Serializing to TOML and parsing again gives the same configuration.
    #[test]
    fn round_trips_through_toml() {
        let config = Config::from_toml(
            r#"
            version = 1
            server = { shutdown_timeout = "1500ms" }
            [listeners.web]
            listen = ["127.0.0.1:8080"]
            protocol = "http"
            "#,
        )
        .unwrap();
        let text = toml::to_string(&config).unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), config);
    }

    /// The version is required, and other versions are rejected where they are written.
    #[test]
    fn checks_version() {
        assert!(parse_error("").message.contains("missing field `version`"));
        let error = parse_error("version = 2\n");
        assert_eq!(error.position, at(1, 11));
        assert_eq!(
            error.message,
            "unsupported configuration version 2, this build reads version 1"
        );

        // Keys of a newer format, sorted before `version`, must not hide the version error.
        let error = parse_error("version = 2\n[gateway]\nworkers = 4\n");
        assert_eq!(error.position, at(1, 11));
    }

    /// Syntax errors carry a position.
    #[test]
    fn locates_syntax_errors() {
        assert_eq!(parse_error("version = 1\n[server\n").position, at(2, 8));
    }

    /// Unknown fields point at the key, so typos are not silently ignored.
    #[test]
    fn rejects_unknown_fields() {
        let error = parse_error("version = 1\n[server]\nthread = 4\n");
        assert_eq!(error.position, at(3, 1));
        assert!(error.message.contains("unknown field `thread`"), "{error}");

        let error = parse_error(
            "version = 1\n[listeners.web]\nlisten = []\nprotocol = \"http\"\nport = 1\n",
        );
        assert_eq!(error.position, at(5, 1));
    }

    /// Bad values point at the value: durations, addresses, names and enums.
    #[test]
    fn locates_value_errors() {
        let error = parse_error("version = 1\n[server]\nshutdown_timeout = \"30\"\n");
        assert_eq!(error.position, at(3, 20));
        assert!(
            error.message.starts_with("invalid duration \"30\""),
            "{error}"
        );

        let error = parse_error("version = 1\n[admin]\nlisten = \"localhost:9090\"\n");
        assert_eq!(error.position, at(3, 10));

        let error = parse_error("version = 1\n[listeners.Web]\nlisten = []\nprotocol = \"http\"\n");
        assert_eq!(error.position, at(2, 12));
        assert!(error.message.starts_with("invalid name \"Web\""), "{error}");

        let error = parse_error("version = 1\n[log]\nformat = \"xml\"\n");
        assert_eq!(error.position, at(3, 10));
    }

    /// Validation problems come back together, after parsing succeeds.
    #[test]
    fn reports_validation_problems() {
        let text = "version = 1\n[listeners.web]\nlisten = []\nprotocol = \"http\"\n";
        match Config::from_toml(text) {
            Err(ConfigError::Invalid(issues)) => {
                assert_eq!(
                    issues,
                    [Issue::new(
                        "listeners.web.listen",
                        "must list at least one address"
                    )]
                );
            }
            other => panic!("expected validation issues, got {other:?}"),
        }
    }
}
