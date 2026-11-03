//! Authentication: the consumers that call the routes with their credentials, the settings
//! that check JWTs, and what each route asks for.

use std::fmt;
use std::path::PathBuf;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{HeaderName, Name, Secret};

/// A client of the routes with authentication, known by its name. With a password it signs in
/// with Basic authentication, its name as the user name; with API keys it sends one of them in
/// a header. Only hashes are kept, never the passwords and keys themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Consumer {
    /// The bcrypt hash of the password, as `htpasswd -nbB <name> <password>` prints it after
    /// the colon, such as `"$2y$05$..."`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<PasswordHash>,
    /// The SHA-256 of each API key, as `sha256:` and 64 hex digits, such as
    /// `printf %s "$KEY" | shasum -a 256` prints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<ApiKeyHash>,
}

/// The bcrypt hash of a password: `$2y$`, `$2b$`, `$2a$` or `$2x$`, a cost from `04` to `31`,
/// `$`, then 53 characters of salt and hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Returns the hash as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `text` is a bcrypt hash, see [`PasswordHash`].
fn is_bcrypt_hash(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digit = |index: usize| bytes[index].is_ascii_digit().then(|| bytes[index] - b'0');
    bytes.len() == 60
        && bytes.starts_with(b"$2")
        && matches!(bytes[2], b'a' | b'b' | b'x' | b'y')
        && bytes[3] == b'$'
        && digit(4)
            .zip(digit(5))
            .is_some_and(|(tens, ones)| (4..=31).contains(&(tens * 10 + ones)))
        && bytes[6] == b'$'
        && bytes[7..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
}

impl TryFrom<String> for PasswordHash {
    type Error = InvalidPasswordHash;

    /// Accepts a bcrypt hash.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_bcrypt_hash(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidPasswordHash)
        }
    }
}

impl From<PasswordHash> for String {
    /// Returns the hash as written.
    fn from(hash: PasswordHash) -> Self {
        hash.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PasswordHash {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PasswordHash".into()
    }

    /// A bcrypt hash; keep in sync with `is_bcrypt_hash`.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^\\$2[abxy]\\$(0[4-9]|[12][0-9]|3[01])\\$[./A-Za-z0-9]{53}$"
        })
    }
}

/// Error for a string that is not a bcrypt hash. It does not repeat the string.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid password hash, expected a bcrypt hash of 60 characters such as htpasswd -nbB prints, starting with \"$2y$\" and a cost from 04 to 31"
)]
pub struct InvalidPasswordHash;

/// The SHA-256 of an API key, written as `sha256:` and 64 hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApiKeyHash([u8; 32]);

impl ApiKeyHash {
    /// What the written form starts with.
    const PREFIX: &str = "sha256:";

    /// Returns the hash.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<String> for ApiKeyHash {
    type Error = InvalidApiKeyHash;

    /// Accepts `sha256:` and 64 hex digits, in either case.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex = value
            .strip_prefix(Self::PREFIX)
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some(hex) = hex else {
            return Err(InvalidApiKeyHash(value));
        };
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let digits = std::str::from_utf8(pair).unwrap_or_default();
            *byte = u8::from_str_radix(digits, 16).map_err(|_| InvalidApiKeyHash(value.clone()))?;
        }
        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for ApiKeyHash {
    /// Takes the SHA-256 of a key.
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ApiKeyHash {
    /// Writes `sha256:` and the hash in lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for ApiKeyHash {
    /// Writes the hash as written in the configuration.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKeyHash({self})")
    }
}

impl From<ApiKeyHash> for String {
    /// Returns the written form, in lowercase.
    fn from(hash: ApiKeyHash) -> Self {
        hash.to_string()
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ApiKeyHash {
    /// Inlined: a named definition would add nothing to a plain string pattern.
    fn inline_schema() -> bool {
        true
    }

    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ApiKeyHash".into()
    }

    /// `sha256:` and 64 hex digits.
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "string", "pattern": "^sha256:[0-9A-Fa-f]{64}$" })
    }
}

/// Error for a string that is not the SHA-256 of an API key.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid API key hash {0:?}, expected \"sha256:\" and the 64 hex digits of the SHA-256 of the key"
)]
pub struct InvalidApiKeyHash(pub String);

/// How the JWTs of an issuer are checked: their signature, with the algorithm and the key of
/// these settings, and their claims. Tokens must carry `exp` and must not have expired, nor be
/// used before `nbf` if they carry it, with 60 seconds of leeway for clocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Jwt {
    /// The algorithm that tokens must be signed with. Tokens that name another one are
    /// rejected, so that a public key never passes for a shared secret.
    pub algorithm: JwtAlgorithm,
    /// PEM file with the public key, or with a certificate of it, for the RS, PS, ES and EdDSA
    /// algorithms. Relative to the configuration file, and read whenever the configuration is
    /// applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PathBuf>,
    /// The shared secret of the HS algorithms: `{ env = "NAME" }` or `{ file = "path" }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    /// The issuer that tokens must name in `iss`. Without it, any issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Audiences, one of which tokens must name in `aud`. Without it, any audience.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// The claim whose value is the consumer, such as a user ID. Default: `"sub"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer_claim: Option<String>,
}

impl Jwt {
    /// Returns the claim whose value is the consumer.
    pub fn consumer_claim(&self) -> &str {
        self.consumer_claim.as_deref().unwrap_or("sub")
    }
}

/// A signature algorithm of JWTs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256, with a shared secret.
    #[serde(rename = "HS256")]
    Hs256,
    /// HMAC with SHA-384, with a shared secret.
    #[serde(rename = "HS384")]
    Hs384,
    /// HMAC with SHA-512, with a shared secret.
    #[serde(rename = "HS512")]
    Hs512,
    /// RSASSA-PKCS1-v1_5 with SHA-256, with an RSA public key.
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384, with an RSA public key.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512, with an RSA public key.
    #[serde(rename = "RS512")]
    Rs512,
    /// RSASSA-PSS with SHA-256, with an RSA public key.
    #[serde(rename = "PS256")]
    Ps256,
    /// RSASSA-PSS with SHA-384, with an RSA public key.
    #[serde(rename = "PS384")]
    Ps384,
    /// RSASSA-PSS with SHA-512, with an RSA public key.
    #[serde(rename = "PS512")]
    Ps512,
    /// ECDSA with P-256 and SHA-256, with an EC public key.
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA with P-384 and SHA-384, with an EC public key.
    #[serde(rename = "ES384")]
    Es384,
    /// Ed25519, with an Ed25519 public key.
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl JwtAlgorithm {
    /// Whether the algorithm signs with a shared secret rather than a key pair.
    pub fn is_hmac(self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }
}

/// The authentication of a route. Requests must show the credentials of a consumer in one of
/// the ways that are on, looked for in this order: an API key, a JWT, then Basic
/// authentication; the first that a request carries decides. Requests without credentials, or
/// with wrong ones, get 401; consumers that `consumers` leaves out get 403. The upstream learns
/// the consumer from header `X-Consumer`, which Wormway removes from every request that arrives
/// with one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RouteAuth {
    /// Basic authentication, with the name and the password of a consumer. Default: `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic: Option<bool>,
    /// An API key of a consumer: `true` for header `X-API-Key`, or `{ header = "..." }` for
    /// another header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<ApiKeyAuth>,
    /// A JWT in `Authorization: Bearer`, checked with these JWT settings. Its consumer is the
    /// value of their `consumer_claim`, which need not name a consumer of the configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Name>,
    /// The consumers that may pass: names of consumers, or claim values of JWTs. Without it,
    /// every consumer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<String>,
}

impl RouteAuth {
    /// Whether Basic authentication is on.
    pub fn basic(&self) -> bool {
        self.basic.unwrap_or(false)
    }

    /// Returns the header that API keys come in, if they are on.
    pub fn api_key_header(&self) -> Option<&str> {
        match &self.api_key {
            Some(ApiKeyAuth::On(true)) => Some(ApiKeyAuth::DEFAULT_HEADER),
            Some(ApiKeyAuth::Header(name)) => Some(name.as_str()),
            Some(ApiKeyAuth::On(false)) | None => None,
        }
    }
}

/// Whether a route takes API keys, and from which header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKeyAuth {
    /// From header `X-API-Key` when `true`, not at all when `false`, written as a boolean.
    On(bool),
    /// From this header, written as `{ header = "X-Token" }`.
    Header(HeaderName),
}

impl ApiKeyAuth {
    /// The header of API keys unless the route names another.
    pub const DEFAULT_HEADER: &str = "X-API-Key";
}

/// The table form of [`ApiKeyAuth`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiKeyTable {
    /// The header.
    header: HeaderName,
}

impl Serialize for ApiKeyAuth {
    /// Writes the boolean or the table.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::On(on) => serializer.serialize_bool(*on),
            Self::Header(header) => ApiKeyTable {
                header: header.clone(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ApiKeyAuth {
    /// Reads either form.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ApiKeyVisitor)
    }
}

/// Reads [`ApiKeyAuth`] from a boolean or a table.
struct ApiKeyVisitor;

impl<'de> Visitor<'de> for ApiKeyVisitor {
    type Value = ApiKeyAuth;

    /// Describes both forms for error messages.
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("true, false, or a table with the header, such as { header = \"X-Token\" }")
    }

    /// Whether API keys come in the default header.
    fn visit_bool<E: de::Error>(self, on: bool) -> Result<ApiKeyAuth, E> {
        Ok(ApiKeyAuth::On(on))
    }

    /// The header that API keys come in.
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<ApiKeyAuth, A::Error> {
        let table = ApiKeyTable::deserialize(MapAccessDeserializer::new(map))?;
        Ok(ApiKeyAuth::Header(table.header))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ApiKeyAuth {
    /// Name of the schema.
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ApiKeyAuth".into()
    }

    /// A boolean, or a table with the header.
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let header = generator.subschema_for::<HeaderName>();
        schemars::json_schema!({
            "description": "true for API keys in header X-API-Key, or { header = \"...\" } for another header.",
            "anyOf": [
                { "type": "boolean" },
                {
                    "type": "object",
                    "properties": { "header": header },
                    "required": ["header"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bcrypt hash of `secret` that `htpasswd -nbB alice secret` printed, with cost 5.
    const HASH: &str = "$2y$05$atrG/e30xORMbAv1bZIkc.h3rExQKJ.8OeGA.FH5MZmlRoe1gClGC";

    /// The SHA-256 of `test`.
    const KEY: &str = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// Password hashes and API key hashes are read and written back, the keys in lowercase.
    #[test]
    fn reads_and_writes_consumers() {
        let upper = KEY.replace("9f86d", "9F86D");
        let consumer: Consumer = toml::from_str(&format!(
            "password_hash = {HASH:?}\napi_keys = [{upper:?}]\n"
        ))
        .unwrap();
        assert_eq!(consumer.password_hash.as_ref().unwrap().as_str(), HASH);
        assert_eq!(consumer.api_keys[0].bytes()[..3], [0x9f, 0x86, 0xd0]);
        assert_eq!(
            ApiKeyHash::from(*consumer.api_keys[0].bytes()).to_string(),
            KEY
        );
        let json = serde_json::to_string(&consumer).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"password_hash":"{HASH}","api_keys":["{KEY}"]}}"#)
        );
        assert_eq!(serde_json::from_str::<Consumer>(&json).unwrap(), consumer);
        assert_eq!(serde_json::to_string(&Consumer::default()).unwrap(), "{}");
    }

    /// Hashes in other forms are rejected, and the message of a password hash does not repeat
    /// it.
    #[test]
    fn rejects_malformed_hashes() {
        // The hash with the characters from `index` on replaced by `text`.
        let with = |index: usize, text: &str| {
            let mut hash = HASH.to_owned();
            hash.replace_range(index..index + text.len(), text);
            hash
        };
        for hash in [
            "",
            &HASH[..59],
            &format!("{HASH}x"),
            &with(2, "z"),
            &with(4, "03"),
            &with(4, "32"),
            &with(4, "5a"),
            &with(6, "."),
            &with(59, "!"),
        ] {
            assert_eq!(
                PasswordHash::try_from(hash.to_owned()),
                Err(InvalidPasswordHash),
                "{hash}"
            );
        }
        let error = toml::from_str::<Consumer>("password_hash = \"plain-text\"\n").unwrap_err();
        assert!(
            error.message().starts_with("invalid password hash"),
            "{error}"
        );
        assert!(!error.message().contains("plain-text"), "{error}");

        for key in [
            &KEY[7..],
            &KEY[..70],
            &format!("{KEY}0"),
            &KEY.replace("sha256:", "sha512:"),
            &KEY.replace("9f", "9g"),
            &KEY.replace("9f", "+f"),
        ] {
            assert!(ApiKeyHash::try_from(key.to_owned()).is_err(), "{key}");
        }
    }

    /// JWT settings name their algorithm as JWTs do, and take the consumer from `sub` unless
    /// they say otherwise.
    #[test]
    fn reads_and_writes_jwt_settings() {
        let jwt: Jwt = toml::from_str(
            "algorithm = \"RS256\"\npublic_key = \"keys/jwt.pub\"\nissuer = \"https://auth.example.com\"\naudience = [\"api\"]\n",
        )
        .unwrap();
        assert_eq!(jwt.algorithm, JwtAlgorithm::Rs256);
        assert!(!jwt.algorithm.is_hmac());
        assert_eq!(jwt.consumer_claim(), "sub");
        let json = serde_json::to_string(&jwt).unwrap();
        assert_eq!(
            json,
            r#"{"algorithm":"RS256","public_key":"keys/jwt.pub","issuer":"https://auth.example.com","audience":["api"]}"#
        );
        assert_eq!(serde_json::from_str::<Jwt>(&json).unwrap(), jwt);

        let hmac: Jwt = toml::from_str(
            "algorithm = \"HS512\"\nsecret = { env = \"JWT_SECRET\" }\nconsumer_claim = \"client_id\"\n",
        )
        .unwrap();
        assert!(hmac.algorithm.is_hmac());
        assert_eq!(hmac.secret, Some(Secret::Env("JWT_SECRET".to_owned())));
        assert_eq!(hmac.consumer_claim(), "client_id");
        let eddsa: Jwt = toml::from_str("algorithm = \"EdDSA\"\n").unwrap();
        assert_eq!(eddsa.algorithm, JwtAlgorithm::EdDsa);

        for text in [
            "algorithm = \"none\"\n",
            "algorithm = \"hs256\"\n",
            "algorithm = \"HS256\"\nleeway = 5\n",
        ] {
            assert!(toml::from_str::<Jwt>(text).is_err(), "{text}");
        }
    }

    /// API keys are on with `true`, in another header with a table, and off otherwise; the
    /// setting is written back in the form it was read.
    #[test]
    fn reads_and_writes_route_auth() {
        let read = |text: &str| toml::from_str::<RouteAuth>(text);
        let auth = read(
            "basic = true\napi_key = true\njwt = \"main\"\nconsumers = [\"alice\", \"auth0|42\"]\n",
        )
        .unwrap();
        assert!(auth.basic());
        assert_eq!(auth.api_key_header(), Some("X-API-Key"));
        assert_eq!(auth.jwt.as_ref().map(Name::as_str), Some("main"));
        assert_eq!(auth.consumers, ["alice", "auth0|42"]);
        let json = serde_json::to_string(&auth).unwrap();
        assert_eq!(
            json,
            r#"{"basic":true,"api_key":true,"jwt":"main","consumers":["alice","auth0|42"]}"#
        );
        assert_eq!(serde_json::from_str::<RouteAuth>(&json).unwrap(), auth);

        let header = read("api_key = { header = \"X-Token\" }\n").unwrap();
        assert!(!header.basic());
        assert_eq!(header.api_key_header(), Some("X-Token"));
        assert_eq!(
            serde_json::to_string(&header).unwrap(),
            r#"{"api_key":{"header":"X-Token"}}"#
        );
        assert_eq!(read("api_key = false\n").unwrap().api_key_header(), None);
        assert_eq!(RouteAuth::default().api_key_header(), None);

        for text in [
            "api_key = \"X-API-Key\"\n",
            "api_key = { header = \"X Token\" }\n",
            "api_key = { header = \"X-Token\", query = \"key\" }\n",
            "jwt = \"Main\"\n",
            "oidc = true\n",
        ] {
            assert!(read(text).is_err(), "{text}");
        }
    }
}
