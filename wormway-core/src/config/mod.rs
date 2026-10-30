//! The configuration model: the types behind `wormway.toml`, parsing and validation.
//!
//! Static settings (`server`, `log`, `admin`, `storage`, `config` and `acme`) are read once at
//! startup. Dynamic settings (`listeners`, `routes`, `upstreams`, `certificates` and the entity
//! tables added later) come from the database or from this file, as chosen by `config.source`, and
//! can change while running.
//!
//! [`Config::from_toml`] loads a configuration in two stages. Parsing checks the syntax and the
//! structure and stops at the first error, which carries a line and column. Validation checks
//! the rules that span fields and reports every problem, each with the path of its setting.

mod action;
mod certificate;
mod duration;
mod error;
mod http;
mod listener;
mod name;
mod route;
mod settings;
mod time_format;
mod upstream;
mod validate;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub use action::{Action, HeaderRules, Redirect, RedirectPart, Respond, Rewrite};
pub use certificate::{AcmeCertificate, AcmeChallenge, Certificate, DnsProvider, Secret};
pub use duration::{Duration, ParseDurationError};
pub use error::{ConfigError, Issue, ParseError, Position};
pub use http::{
    HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue, InvalidMethod, Method,
};
pub use listener::{HttpSettings, Listener, ListenerTls, Protocol, UnknownSni};
pub use name::{InvalidName, Name};
pub use route::{
    HeaderCondition, HostPattern, InvalidHostPattern, InvalidRegex, PathPattern, PathRegex, Route,
    RouteMatch,
};
pub use settings::{
    AccessLogFormat, AccessLogSettings, AcmeSettings, AdminSettings, ConfigSettings, ConfigSource,
    LogFormat, LogSettings, ServerSettings, StorageSettings, TimeZone,
};
pub use time_format::{InvalidTimeFormat, TimeFormat};
pub use upstream::{
    Balance, HashKey, HealthCheck, HealthCheckKind, InvalidTargetAddress, PassiveCheck,
    RouteTimeouts, Target, TargetAddress, Timeouts, Upstream, UpstreamProtocol, UpstreamTls,
};

/// The configuration file, `wormway.toml`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(title = "Wormway configuration"))]
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
    /// Where Wormway keeps its database and runtime state. Static: a restart applies changes.
    #[serde(default)]
    pub storage: StorageSettings,
    /// Where the dynamic settings come from. Static: a restart applies changes.
    #[serde(default)]
    pub config: ConfigSettings,
    /// How certificates are got through ACME. Static: a restart applies changes.
    #[serde(default)]
    pub acme: AcmeSettings,
    /// Listeners by name. Dynamic: read from this file only when `config.source` is `"file"`.
    #[serde(default)]
    pub listeners: BTreeMap<Name, Listener>,
    /// Routes of the HTTP listeners by name. Dynamic: read from this file only when
    /// `config.source` is `"file"`.
    #[serde(default)]
    pub routes: BTreeMap<Name, Route>,
    /// Upstreams by name. Dynamic: read from this file only when `config.source` is `"file"`.
    #[serde(default)]
    pub upstreams: BTreeMap<Name, Upstream>,
    /// TLS certificates by name. Dynamic: read from this file only when `config.source` is
    /// `"file"`.
    #[serde(default)]
    pub certificates: BTreeMap<Name, Certificate>,
}

impl Config {
    /// Parses TOML text and validates the result.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config = parse(text)?;
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

    /// Returns a copy of the dynamic settings.
    pub fn dynamic(&self) -> DynamicConfig {
        self.clone().into_dynamic()
    }

    /// Takes the dynamic settings out, dropping the static ones.
    pub fn into_dynamic(self) -> DynamicConfig {
        // Keep in sync with the dynamic fields of `Config`.
        DynamicConfig {
            listeners: self.listeners,
            routes: self.routes,
            upstreams: self.upstreams,
            certificates: self.certificates,
        }
    }

    /// Replaces the dynamic settings and keeps the static ones.
    pub fn set_dynamic(&mut self, dynamic: DynamicConfig) {
        // Keep in sync with the dynamic fields of `Config`.
        self.listeners = dynamic.listeners;
        self.routes = dynamic.routes;
        self.upstreams = dynamic.upstreams;
        self.certificates = dynamic.certificates;
    }

    /// Whether `other` has the same static settings.
    pub fn same_static(&self, other: &Config) -> bool {
        let without_dynamic = |config: &Config| {
            let mut config = config.clone();
            config.set_dynamic(DynamicConfig::default());
            config
        };
        without_dynamic(self) == without_dynamic(other)
    }
}

/// The dynamic settings: the entity tables that can change while Wormway runs. The database
/// stores them and the Admin API exchanges them as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicConfig {
    /// Listeners by name.
    #[serde(default)]
    pub listeners: BTreeMap<Name, Listener>,
    /// Routes of the HTTP listeners by name.
    #[serde(default)]
    pub routes: BTreeMap<Name, Route>,
    /// Upstreams by name.
    #[serde(default)]
    pub upstreams: BTreeMap<Name, Upstream>,
    /// TLS certificates by name.
    #[serde(default)]
    pub certificates: BTreeMap<Name, Certificate>,
}

impl DynamicConfig {
    /// Reads the dynamic settings from text in the format of `wormway.toml`, such as the output of
    /// [`DynamicConfig::to_toml`] or a whole configuration file. Static settings in the text are
    /// parsed and then ignored. Rules are not checked: they also depend on the static settings
    /// of the instance that applies the result.
    pub fn from_toml(text: &str) -> Result<Self, ParseError> {
        parse(text).map(Config::into_dynamic)
    }

    /// Writes the dynamic settings in the format of `wormway.toml`: the format version, then the
    /// tables.
    pub fn to_toml(&self) -> Result<String, impl std::error::Error + Send + Sync + 'static> {
        toml::to_string_pretty(&DynamicFile {
            version: Version::CURRENT,
            dynamic: self,
        })
    }
}

/// What [`DynamicConfig::to_toml`] writes.
#[derive(Serialize)]
struct DynamicFile<'a> {
    /// Version of the format, as in `wormway.toml`.
    version: Version,
    /// The tables.
    #[serde(flatten)]
    dynamic: &'a DynamicConfig,
}

/// Parses TOML text into a configuration without validating it.
fn parse(text: &str) -> Result<Config, ParseError> {
    // Check the version first. Tables are deserialized in key order rather than file order, so
    // in one pass an unknown key could hide the version error of a newer file.
    toml::from_str::<Header>(text).map_err(|e| ParseError::from_toml(&e, text))?;
    toml::from_str(text).map_err(|e| ParseError::from_toml(&e, text))
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
/// completion and validation, and `wormway schema` prints it.
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
    use std::path::PathBuf;

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
        assert_eq!(config.admin.listen, "127.0.0.1:9872".parse().unwrap());
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
            token_file = "/run/secrets/wormway"
            [storage]
            data_dir = "/var/lib/wormway"
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

    /// The access log is off until `[log.access]` turns it on, as JSON to standard output unless
    /// set otherwise; routes go to it unless they opt out.
    #[test]
    fn reads_access_log_settings() {
        let plain = Config::from_toml("version = 1").unwrap();
        assert_eq!(plain.log.access, None);
        let config = Config::from_toml(
            "version = 1\n[log.access]\n[routes.quiet]\naccess_log = false\nrespond = { status = 204 }\n",
        )
        .unwrap();
        let access = config.log.access.clone().unwrap();
        assert_eq!(access.format, AccessLogFormat::Json);
        assert_eq!(access.path, None);
        assert!(!config.routes["quiet"].access_log());
        assert!(Route::default().access_log());
        let text = toml::to_string(&config).unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), config);

        let config = Config::from_toml(
            "version = 1\n[log.access]\nformat = \"combined\"\npath = \"logs/access.log\"\n",
        )
        .unwrap();
        let access = config.log.access.unwrap();
        assert_eq!(access.format, AccessLogFormat::Combined);
        assert_eq!(access.path, Some(PathBuf::from("logs/access.log")));
        let error = parse_error("version = 1\n[log.access]\nformat = \"apache\"\n");
        assert!(error.to_string().contains("apache"), "{error}");
    }

    /// The logs write times in RFC 3339 and UTC unless `log` sets a strftime pattern or the
    /// local time zone; patterns that chrono cannot read are rejected.
    #[test]
    fn reads_log_time_settings() {
        let plain = Config::from_toml("version = 1").unwrap();
        assert_eq!(plain.log.time_format, None);
        assert_eq!(plain.log.time_zone, TimeZone::Utc);
        let config = Config::from_toml(
            "version = 1\n[log]\ntime_format = \"%Y-%m-%d %H:%M:%S%.3f\"\ntime_zone = \"local\"\n",
        )
        .unwrap();
        let format = config.log.time_format.as_ref().map(TimeFormat::as_str);
        assert_eq!(format, Some("%Y-%m-%d %H:%M:%S%.3f"));
        assert_eq!(config.log.time_zone, TimeZone::Local);
        let text = toml::to_string(&config).unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), config);

        for pattern in ["%Y-%Q", "%", ""] {
            let error = parse_error(&format!("version = 1\n[log]\ntime_format = {pattern:?}\n"));
            assert_eq!(error.position, at(3, 15), "{error}");
            assert!(
                error
                    .message
                    .starts_with(&format!("invalid time format {pattern:?}")),
                "{error}"
            );
        }
        let error = parse_error("version = 1\n[log]\ntime_zone = \"Asia/Shanghai\"\n");
        assert!(error.to_string().contains("Asia/Shanghai"), "{error}");
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

        let error = parse_error("version = 1\n[admin]\nlisten = \"localhost:9872\"\n");
        assert_eq!(error.position, at(3, 10));

        let error = parse_error("version = 1\n[listeners.Web]\nlisten = []\nprotocol = \"http\"\n");
        assert_eq!(error.position, at(2, 12));
        assert!(error.message.starts_with("invalid name \"Web\""), "{error}");

        let error = parse_error("version = 1\n[log]\nformat = \"xml\"\n");
        assert_eq!(error.position, at(3, 10));
    }

    /// Dynamic settings can be swapped or cleared while the static ones stay.
    #[test]
    fn separates_static_and_dynamic_settings() {
        let web = "[listeners.web]\nlisten = [\"127.0.0.1:8080\"]\nprotocol = \"http\"\n";
        let running = Config::from_toml("version = 1\n[server]\nthreads = 2\n").unwrap();
        let file =
            Config::from_toml(&format!("version = 1\n[server]\nthreads = 4\n{web}")).unwrap();
        assert!(!running.same_static(&file));

        let mut next = running.clone();
        next.set_dynamic(file.dynamic());
        assert_eq!(next.server.threads, 2);
        assert_eq!(next.listeners, file.listeners);
        assert!(next.same_static(&running));
        assert_eq!(next.clone().into_dynamic(), file.into_dynamic());

        next.set_dynamic(DynamicConfig::default());
        assert_eq!(next, running);
    }

    /// The dynamic settings travel as JSON with the same keys as the file, and unknown keys are
    /// rejected there too.
    #[test]
    fn dynamic_settings_round_trip_through_json() {
        let json = r#"{"listeners":{"web":{"listen":["127.0.0.1:8080"],"protocol":"http"}},"routes":{"api":{"match":{"paths":["/api/"]},"upstream":"api"}},"upstreams":{"api":{"targets":["127.0.0.1:9000"]}},"certificates":{}}"#;
        let dynamic: DynamicConfig = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&dynamic).unwrap(), json);
        assert!(serde_json::from_str::<DynamicConfig>(r#"{"route":{}}"#).is_err());
    }

    /// The dynamic settings are written in the format of `wormway.toml` and read back; a whole
    /// configuration file gives its dynamic settings.
    #[test]
    fn dynamic_settings_round_trip_through_toml() {
        let text = "version = 1\n[server]\nthreads = 4\n[listeners.web]\nlisten = [\"127.0.0.1:8080\"]\nprotocol = \"http\"\n";
        let dynamic = DynamicConfig::from_toml(text).unwrap();
        assert_eq!(dynamic, Config::from_toml(text).unwrap().into_dynamic());

        let written = dynamic.to_toml().unwrap();
        assert!(written.starts_with("version = 1\n"), "{written}");
        assert!(!written.contains("threads"), "{written}");
        assert_eq!(DynamicConfig::from_toml(&written).unwrap(), dynamic);

        let empty = DynamicConfig::default().to_toml().unwrap();
        assert_eq!(
            DynamicConfig::from_toml(&empty).unwrap(),
            DynamicConfig::default()
        );
    }

    /// Reading dynamic settings checks the version and the structure, but not the rules.
    #[test]
    fn reads_dynamic_settings_without_validating() {
        let error = DynamicConfig::from_toml("[listeners]\n").unwrap_err();
        assert!(error.message.contains("missing field `version`"), "{error}");
        let error = DynamicConfig::from_toml(
            "version = 1\n[listeners.web]\nlisten = []\nprotocol = \"http\"\nport = 1\n",
        )
        .unwrap_err();
        assert_eq!(error.position, at(5, 1));

        // An empty address list breaks a rule, which the instance that applies it checks.
        let dynamic = DynamicConfig::from_toml(
            "version = 1\n[listeners.web]\nlisten = []\nprotocol = \"http\"\n",
        )
        .unwrap();
        assert_eq!(dynamic.listeners.len(), 1);
    }

    /// Returns the problems of a file configuration with `text` added, as `path: message`.
    fn problems(text: &str) -> Vec<String> {
        let text = format!("version = 1\n[config]\nsource = \"file\"\n{text}");
        match Config::from_toml(&text) {
            Err(ConfigError::Invalid(issues)) => issues.iter().map(Issue::to_string).collect(),
            other => panic!("expected validation issues, got {other:?}"),
        }
    }

    /// Certificates come from files or through ACME, whose certificate authority `[acme]`
    /// names; a DNS provider holds a reference to its token, not the token.
    #[test]
    fn reads_acme_settings() {
        let plain = Config::from_toml("version = 1").unwrap();
        assert_eq!(plain.acme.directory_url(), AcmeSettings::LETSENCRYPT);
        let config = Config::from_toml(
            r#"
            version = 1
            [acme]
            directory = "letsencrypt-staging"
            email = "ops@example.com"
            ca = "certs/ca.pem"
            [config]
            source = "file"
            [certificates.site]
            acme = { domains = ["Example.com", "www.example.com"] }
            [certificates.wild]
            acme = { domains = ["*.example.com"], challenge = "dns-01", dns = { provider = "cloudflare", api_token = { env = "CF_API_TOKEN" } } }
            [certificates.files]
            cert = "a.crt"
            key = "a.key"
            "#,
        )
        .unwrap();
        assert_eq!(
            config.acme.directory_url(),
            AcmeSettings::LETSENCRYPT_STAGING
        );
        let site = config.certificates["site"].acme.as_ref().unwrap();
        assert_eq!(site.domains[0].as_str(), "example.com");
        assert_eq!(site.challenge, AcmeChallenge::Http01);
        let wild = config.certificates["wild"].acme.as_ref().unwrap();
        let token = Secret::Env("CF_API_TOKEN".to_owned());
        assert_eq!(wild.dns, Some(DnsProvider::Cloudflare { api_token: token }));
        let text = toml::to_string(&config).unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), config);

        let custom =
            Config::from_toml("version = 1\n[acme]\ndirectory = \"https://ca.internal/dir\"\n")
                .unwrap();
        assert_eq!(custom.acme.directory_url(), "https://ca.internal/dir");
        for text in [
            "[certificates.a]\nacme = { domains = [\"a.com\"], dns = { provider = \"route53\" } }\n",
            "[certificates.a]\nacme = { domains = [\"a.com\"], challenge = \"dns-01\", dns = { provider = \"cloudflare\", api_token = { vault = \"x\" } } }\n",
            "[certificates.a]\nacme = { domains = [\"a.com\"], challenge = \"dns-01\", dns = { provider = \"cloudflare\", api_token = { env = \"X\" }, zone = \"a.com\" } }\n",
            "[certificates.a]\nacme = { domains = [\"a.com\"], challenge = \"tls-alpn-01\" }\n",
        ] {
            parse_error(&format!("version = 1\n{text}"));
        }
    }

    /// A certificate needs either both files or ACME, and its ACME settings must fit together.
    #[test]
    fn checks_acme_settings() {
        assert_eq!(
            problems("[certificates.a]\ncert = \"a.crt\"\n"),
            ["certificates.a: set cert and key, or acme"]
        );
        assert_eq!(
            problems(
                "[certificates.a]\ncert = \"a.crt\"\nkey = \"a.key\"\nacme = { domains = [\"a.com\"] }\n"
            ),
            ["certificates.a: set either cert and key, or acme"]
        );
        assert_eq!(
            problems("[certificates.a]\nacme = { domains = [] }\n"),
            ["certificates.a.acme.domains: must list at least one host name"]
        );
        let names = r#"["localhost", "10.0.0.1", "*.a.com", "a.com", "A.com"]"#;
        let host = "must be a host name with a dot, such as example.com, not an IP address";
        assert_eq!(
            problems(&format!(
                "[certificates.a]\nacme = {{ domains = {names} }}\n"
            )),
            [
                format!("certificates.a.acme.domains[0]: {host}"),
                format!("certificates.a.acme.domains[1]: {host}"),
                "certificates.a.acme.domains[2]: wildcard names need challenge = \"dns-01\""
                    .to_owned(),
                "certificates.a.acme.domains[4]: listed twice".to_owned(),
            ]
        );
        assert_eq!(
            problems(
                "[certificates.a]\nacme = { domains = [\"a.com\"], challenge = \"dns-01\" }\n"
            ),
            ["certificates.a.acme.dns: needed by challenge = \"dns-01\""]
        );
        assert_eq!(
            problems(
                "[certificates.a]\nacme = { domains = [\"a.com\"], dns = { provider = \"cloudflare\", api_token = { file = \"token\" } } }\n"
            ),
            ["certificates.a.acme.dns: only for challenge = \"dns-01\""]
        );
        assert_eq!(
            problems("[acme]\ndirectory = \"http://ca.internal/dir\"\nemail = \"nobody\"\n"),
            [
                "acme.directory: must be \"letsencrypt\", \"letsencrypt-staging\" or an https:// URL",
                "acme.email: must be an email address",
            ]
        );
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
