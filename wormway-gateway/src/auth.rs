//! Authentication of routes: the credentials of consumers in API keys, JWTs and Basic
//! authentication, checked against the consumers and the JWT settings of the configuration.
//!
//! bcrypt takes milliseconds of CPU on purpose, so Basic passwords are checked on the blocking
//! pool, at most one per CPU core at once, and credentials that it accepted are taken for five
//! minutes without checking them again, as long as the consumer keeps the same password hash.

use std::collections::{HashMap, HashSet};
use std::num::NonZero;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::header::AUTHORIZATION;
use http::{HeaderName, HeaderValue};
use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation};
use pingora::http::RequestHeader;
use quick_cache::sync::Cache;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use wormway_core::config::{Config, Issue, Jwt, JwtAlgorithm, Name, RouteAuth};

use crate::headers::random;

/// How long Basic credentials that bcrypt accepted are taken without checking them again.
const ACCEPTED_FOR: Duration = Duration::from_secs(5 * 60);
/// Most Basic credentials kept as accepted.
const MAX_ACCEPTED: usize = 10_000;
/// The realm of the challenges of 401 answers.
const REALM: &str = "wormway";

/// The consumers and the JWT settings of a configuration, ready to check credentials.
pub(crate) struct Consumers {
    /// The bcrypt hash of the password of each consumer that has one.
    passwords: HashMap<Name, Arc<str>>,
    /// The consumer of each API key, by the SHA-256 of the key.
    api_keys: HashMap<[u8; 32], Name>,
    /// The JWT settings, by name.
    jwt: HashMap<Name, Arc<JwtCheck>>,
    /// The checks of Basic passwords, which the configurations share.
    checks: Arc<PasswordChecks>,
}

impl Consumers {
    /// Reads the consumers and the JWT settings of `config`, the keys and the secrets of the
    /// JWT settings on the blocking pool, with paths relative to `base`. Basic passwords are
    /// checked through `checks`.
    pub(crate) async fn load(
        config: &Config,
        base: &Path,
        checks: Arc<PasswordChecks>,
    ) -> Result<Self, Vec<Issue>> {
        let (settings, base) = (config.jwt.clone(), base.to_owned());
        let loaded = tokio::task::spawn_blocking(move || {
            settings
                .iter()
                .map(|(name, jwt)| {
                    JwtCheck::load(name, jwt, &base).map(|check| (name.clone(), Arc::new(check)))
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|error| vec![Issue::new("jwt", format!("cannot read the keys: {error}"))])?;
        let mut jwt = HashMap::new();
        let mut issues = Vec::new();
        for loaded in loaded {
            match loaded {
                Ok((name, check)) => {
                    jwt.insert(name, check);
                }
                Err(issue) => issues.push(issue),
            }
        }
        if !issues.is_empty() {
            return Err(issues);
        }
        let passwords = config
            .consumers
            .iter()
            .filter_map(|(name, consumer)| {
                let hash = consumer.password_hash.as_ref()?;
                Some((name.clone(), Arc::from(hash.as_str())))
            })
            .collect();
        let api_keys = config
            .consumers
            .iter()
            .flat_map(|(name, consumer)| {
                consumer
                    .api_keys
                    .iter()
                    .map(move |key| (*key.bytes(), name.clone()))
            })
            .collect();
        Ok(Self {
            passwords,
            api_keys,
            jwt,
            checks,
        })
    }

    /// Returns the consumer of API key `key`.
    fn api_key(&self, key: &[u8]) -> Result<String, &'static str> {
        let hash: [u8; 32] = Sha256::digest(key).into();
        self.api_keys
            .get(&hash)
            .map(Name::to_string)
            .ok_or("unknown API key")
    }

    /// Returns the consumer of Basic credentials `encoded`, in base64, once bcrypt accepts the
    /// password for the hash of the consumer, or accepted it lately.
    async fn basic(&self, encoded: &[u8]) -> Result<String, &'static str> {
        let malformed = "malformed Basic credentials";
        let credentials = BASE64.decode(encoded).map_err(|_| malformed)?;
        let colon = credentials
            .iter()
            .position(|&b| b == b':')
            .ok_or(malformed)?;
        let (name, password) = (&credentials[..colon], &credentials[colon + 1..]);
        let (name, hash) = std::str::from_utf8(name)
            .ok()
            .and_then(|name| self.passwords.get_key_value(name))
            .ok_or("unknown consumer")?;
        let key = self.checks.key(&credentials);
        if self.checks.accepted(&key, hash, Instant::now()) {
            return Ok(name.to_string());
        }
        match self.checks.verify(password.to_vec(), hash.clone()).await {
            Ok(true) => {
                self.checks.accept(key, hash.clone(), Instant::now());
                Ok(name.to_string())
            }
            Ok(false) => Err("wrong password"),
            Err(error) => {
                tracing::error!(consumer = %name, "cannot check the password: {error}");
                Err("password not checked")
            }
        }
    }
}

/// The checks of Basic passwords, which the configurations share: the credentials that bcrypt
/// accepted lately, and how many checks may run at once.
pub(crate) struct PasswordChecks {
    /// The password hash that each credential matched, and when, by the SHA-256 of the salt and
    /// the credential.
    accepted: Cache<[u8; 32], (Arc<str>, Instant)>,
    /// Random bytes hashed in front of each credential, so that the keys do not give the
    /// passwords away.
    salt: [u8; 16],
    /// One permit per CPU core: a flood of guesses waits for them rather than taking every core
    /// from the other requests.
    permits: Arc<Semaphore>,
}

impl Default for PasswordChecks {
    /// No credentials accepted yet, a new salt, and a permit per CPU core.
    fn default() -> Self {
        let mut salt = [0; 16];
        // The generator of aws-lc does not fail in practice; a salt of zeros would still keep
        // the passwords out of the keys of the cache, if less well.
        let _ = random().fill(&mut salt);
        let cores = std::thread::available_parallelism().map_or(1, NonZero::get);
        Self {
            accepted: Cache::new(MAX_ACCEPTED),
            salt,
            permits: Arc::new(Semaphore::new(cores)),
        }
    }
}

impl PasswordChecks {
    /// Returns the key of `credentials`, the user name and the password as sent.
    fn key(&self, credentials: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.salt)
            .chain_update(credentials)
            .finalize()
            .into()
    }

    /// Whether bcrypt accepted the credentials of `key` for password hash `hash` less than
    /// [`ACCEPTED_FOR`] before `now`.
    fn accepted(&self, key: &[u8; 32], hash: &str, now: Instant) -> bool {
        self.accepted.get(key).is_some_and(|(matched, at)| {
            *matched == *hash && now.saturating_duration_since(at) < ACCEPTED_FOR
        })
    }

    /// Notes that bcrypt accepted the credentials of `key` for password hash `hash` at `now`.
    fn accept(&self, key: [u8; 32], hash: Arc<str>, now: Instant) {
        self.accepted.insert(key, (hash, now));
    }

    /// Whether `password` matches bcrypt hash `hash`, checked on the blocking pool once a
    /// permit is free.
    async fn verify(&self, password: Vec<u8>, hash: Arc<str>) -> Result<bool, String> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| error.to_string())?;
        tokio::task::spawn_blocking(move || {
            // The permit goes with the check, which runs to its end even if the request stops
            // waiting for it.
            let _permit = permit;
            bcrypt::verify(password, &hash)
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
    }
}

/// JWT settings ready to check tokens.
pub(crate) struct JwtCheck {
    /// The key that checks the signatures.
    key: DecodingKey,
    /// The algorithm and the claims that tokens must have.
    validation: Validation,
    /// The claim whose value is the consumer.
    claim: String,
}

impl JwtCheck {
    /// Reads the key of `settings`, the JWT settings `name`, with paths relative to `base`. It
    /// reads files, so call it on the blocking pool.
    fn load(name: &Name, settings: &Jwt, base: &Path) -> Result<Self, Issue> {
        let algorithm = algorithm(settings.algorithm);
        let key = match algorithm.family() {
            AlgorithmFamily::Hmac => {
                DecodingKey::from_secret(shared_secret(name, settings, base)?.as_bytes())
            }
            AlgorithmFamily::Rsa => {
                public_key(name, settings, base, "RSA", DecodingKey::from_rsa_pem)?
            }
            AlgorithmFamily::Ec => {
                public_key(name, settings, base, "EC", DecodingKey::from_ec_pem)?
            }
            AlgorithmFamily::Ed => {
                public_key(name, settings, base, "Ed25519", DecodingKey::from_ed_pem)?
            }
        };
        let mut validation = Validation::new(algorithm);
        validation.validate_nbf = true;
        let mut required = vec!["exp"];
        if let Some(issuer) = &settings.issuer {
            validation.set_issuer(&[issuer]);
            required.push("iss");
        }
        // jsonwebtoken checks the audience only of tokens that name one, and without audiences
        // of its own refuses every token that does: settings with audiences need one in every
        // token, and settings without take any.
        if settings.audience.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&settings.audience);
            required.push("aud");
        }
        validation.set_required_spec_claims(&required);
        Ok(Self {
            key,
            validation,
            claim: settings.consumer_claim().to_owned(),
        })
    }

    /// Returns the consumer of `token`, the value of the claim of the settings, once its
    /// signature and its claims pass; otherwise why the token is refused.
    fn consumer(&self, token: &[u8]) -> Result<String, &'static str> {
        let token = jsonwebtoken::decode::<Map<String, Value>>(token, &self.key, &self.validation)
            .map_err(|error| refusal(error.kind()))?;
        let consumer = match token.claims.get(&self.claim) {
            Some(Value::String(consumer)) => consumer.clone(),
            Some(Value::Number(number)) if number.is_i64() || number.is_u64() => number.to_string(),
            _ => return Err("token without its consumer claim"),
        };
        // The consumer goes to the upstream in a header.
        if consumer.is_empty() || HeaderValue::from_str(&consumer).is_err() {
            return Err("token with a consumer that cannot be a header value");
        }
        Ok(consumer)
    }
}

/// Returns the algorithm of jsonwebtoken that `algorithm` names.
fn algorithm(algorithm: JwtAlgorithm) -> Algorithm {
    match algorithm {
        JwtAlgorithm::Hs256 => Algorithm::HS256,
        JwtAlgorithm::Hs384 => Algorithm::HS384,
        JwtAlgorithm::Hs512 => Algorithm::HS512,
        JwtAlgorithm::Rs256 => Algorithm::RS256,
        JwtAlgorithm::Rs384 => Algorithm::RS384,
        JwtAlgorithm::Rs512 => Algorithm::RS512,
        JwtAlgorithm::Ps256 => Algorithm::PS256,
        JwtAlgorithm::Ps384 => Algorithm::PS384,
        JwtAlgorithm::Ps512 => Algorithm::PS512,
        JwtAlgorithm::Es256 => Algorithm::ES256,
        JwtAlgorithm::Es384 => Algorithm::ES384,
        JwtAlgorithm::EdDsa => Algorithm::EdDSA,
    }
}

/// Reads the shared secret of `settings`, the JWT settings `name`, with a path relative to
/// `base`.
fn shared_secret(name: &Name, settings: &Jwt, base: &Path) -> Result<String, Issue> {
    let at = format!("jwt.{name}.secret");
    let secret = settings
        .secret
        .as_ref()
        .ok_or_else(|| Issue::new(&at, "needed by the HS algorithms"))?;
    secret
        .read(base)
        .map_err(|problem| Issue::new(&at, problem))
}

/// Reads the public key of `settings`, the JWT settings `name`, from its PEM file relative to
/// `base`, with `parse`, which takes `kind` public keys.
fn public_key(
    name: &Name,
    settings: &Jwt,
    base: &Path,
    kind: &str,
    parse: fn(&[u8]) -> JwtResult<DecodingKey>,
) -> Result<DecodingKey, Issue> {
    let at = format!("jwt.{name}.public_key");
    let path = settings
        .public_key
        .as_ref()
        .ok_or_else(|| Issue::new(&at, "needed by the RS, PS, ES and EdDSA algorithms"))?;
    let path = base.join(path);
    let pem = std::fs::read(&path)
        .map_err(|error| Issue::new(&at, format!("cannot read {}: {error}", path.display())))?;
    parse(&pem).map_err(|error| {
        let problem = format!(
            "{} holds no {kind} public key in PEM: {error}",
            path.display()
        );
        Issue::new(&at, problem)
    })
}

/// Returns why a token is refused, for the logs.
fn refusal(kind: &ErrorKind) -> &'static str {
    match kind {
        ErrorKind::ExpiredSignature => "token expired",
        ErrorKind::ImmatureSignature => "token not valid yet",
        ErrorKind::InvalidSignature => "token with a wrong signature",
        ErrorKind::InvalidAlgorithm => "token signed with another algorithm",
        ErrorKind::InvalidIssuer => "token from another issuer",
        ErrorKind::InvalidAudience => "token for another audience",
        ErrorKind::MissingRequiredClaim(_) => "token without a required claim",
        _ => "malformed token",
    }
}

/// The authentication of a route, ready to check requests.
pub(crate) struct Authentication {
    /// The consumers and the JWT settings of the configuration.
    consumers: Arc<Consumers>,
    /// The header that API keys come in, if the route takes them.
    api_key: Option<HeaderName>,
    /// The JWT settings that check tokens, if the route takes them.
    jwt: Option<Arc<JwtCheck>>,
    /// Whether the route takes Basic authentication.
    basic: bool,
    /// The consumers that may pass, unless all may.
    allowed: Option<HashSet<String>>,
    /// The `WWW-Authenticate` values of 401 answers: one for each way the route takes.
    pub(crate) challenges: Vec<HeaderValue>,
}

impl Authentication {
    /// Compiles `auth`, the authentication of route `name`, with `consumers`. The route passed
    /// validation, so this fails only if the validation rules miss a case.
    pub(crate) fn new(
        name: &Name,
        auth: &RouteAuth,
        consumers: &Arc<Consumers>,
    ) -> Result<Self, Issue> {
        let at = |field: &str| format!("routes.{name}.auth{field}");
        let jwt = match &auth.jwt {
            Some(jwt) => Some(
                consumers
                    .jwt
                    .get(jwt)
                    .cloned()
                    .ok_or_else(|| Issue::new(at(".jwt"), format!("unknown jwt \"{jwt}\"")))?,
            ),
            None => None,
        };
        let mut challenges = Vec::new();
        let api_key = match auth.api_key_header() {
            Some(header) => {
                challenges.push(format!("ApiKey header=\"{header}\""));
                let name = HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
                    Issue::new(at(".api_key"), format!("header name {header:?}: {error}"))
                })?;
                Some(name)
            }
            None => None,
        };
        if jwt.is_some() {
            challenges.push(format!("Bearer realm=\"{REALM}\""));
        }
        if auth.basic() {
            challenges.push(format!("Basic realm=\"{REALM}\", charset=\"UTF-8\""));
        }
        let challenges = challenges
            .iter()
            .map(|challenge| HeaderValue::from_str(challenge))
            .collect::<Result<_, _>>()
            .map_err(|error| Issue::new(at(""), format!("challenge: {error}")))?;
        Ok(Self {
            consumers: consumers.clone(),
            api_key,
            jwt,
            basic: auth.basic(),
            allowed: (!auth.consumers.is_empty()).then(|| auth.consumers.iter().cloned().collect()),
            challenges,
        })
    }

    /// Checks the credentials of `request`: of the ways that the route takes, the first that
    /// the request carries decides, in this order: an API key, a JWT, then Basic
    /// authentication. Returns the consumer, or why the request has none.
    pub(crate) async fn check(&self, request: &RequestHeader) -> Result<String, &'static str> {
        if let Some(header) = &self.api_key
            && let Some(key) = request.headers.get(header)
        {
            return self.consumers.api_key(key.as_bytes());
        }
        if let Some(jwt) = &self.jwt
            && let Some(token) = authorization(request, "Bearer")
        {
            return jwt.consumer(token);
        }
        if self.basic
            && let Some(credentials) = authorization(request, "Basic")
        {
            return self.consumers.basic(credentials).await;
        }
        Err("no credentials")
    }

    /// Whether `consumer` may use the route.
    pub(crate) fn allows(&self, consumer: &str) -> bool {
        self.allowed
            .as_ref()
            .is_none_or(|allowed| allowed.contains(consumer))
    }
}

/// Returns the credentials in the `Authorization` header of `request` if it uses `scheme`,
/// whatever its case.
fn authorization<'a>(request: &'a RequestHeader, scheme: &str) -> Option<&'a [u8]> {
    let value = request.headers.get(AUTHORIZATION)?.as_bytes();
    let space = value.iter().position(|&b| b == b' ')?;
    let (name, credentials) = value.split_at(space);
    name.eq_ignore_ascii_case(scheme.as_bytes())
        .then(|| credentials.trim_ascii())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    use super::*;

    /// The SHA-256 of `test`.
    const TEST_KEY: &str =
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// Parses a configuration, adding `version = 1` in front.
    fn parse(text: &str) -> Config {
        Config::from_toml(&format!("version = 1\n{text}")).unwrap()
    }

    /// The consumers and the JWT settings of `text`, with files relative to `base`.
    async fn consumers(text: &str, base: &Path) -> Arc<Consumers> {
        let config = parse(text);
        Arc::new(
            Consumers::load(&config, base, Arc::default())
                .await
                .unwrap(),
        )
    }

    /// The authentication of route `api` in `text`, with the consumers of `consumers`.
    fn authentication(text: &str, consumers: &Arc<Consumers>) -> Authentication {
        let config = parse(text);
        let auth = config.routes["api"].auth.as_ref().unwrap();
        Authentication::new(&"api".parse().unwrap(), auth, consumers).unwrap()
    }

    /// Checks a request with `headers` against `auth`.
    async fn check(
        auth: &Authentication,
        headers: &[(&str, &str)],
    ) -> Result<String, &'static str> {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        for (name, value) in headers {
            request.append_header(name.to_string(), *value).unwrap();
        }
        auth.check(&request).await
    }

    /// The `Authorization` value of Basic credentials `user` and `password`.
    fn basic(user: &str, password: &str) -> String {
        format!("Basic {}", BASE64.encode(format!("{user}:{password}")))
    }

    /// API keys and Basic passwords name their consumer; the first kind of credentials that a
    /// request carries decides, and kinds the route does not take do not count.
    #[tokio::test]
    async fn checks_api_keys_and_passwords() {
        let (secret, colon) = (
            bcrypt::hash("secret", 4).unwrap(),
            bcrypt::hash("a:b", 4).unwrap(),
        );
        let consumers = consumers(
            &format!(
                "[consumers.alice]\npassword_hash = \"{secret}\"\napi_keys = [\"{TEST_KEY}\"]\n\
                 [consumers.bob]\n[consumers.carol]\npassword_hash = \"{colon}\"\n"
            ),
            Path::new("."),
        )
        .await;
        let auth = authentication(
            "[routes.api]\nrespond = { status = 204 }\nauth = { basic = true, api_key = true }\n",
            &consumers,
        );
        let alice = Ok("alice".to_owned());
        assert_eq!(check(&auth, &[("X-API-Key", "test")]).await, alice);
        assert_eq!(
            check(&auth, &[("x-api-key", "wrong")]).await,
            Err("unknown API key")
        );
        assert_eq!(
            check(&auth, &[("Authorization", &basic("alice", "secret"))]).await,
            alice
        );
        let lowercase = basic("alice", "secret").replace("Basic", "basic");
        assert_eq!(check(&auth, &[("Authorization", &lowercase)]).await, alice);
        let wrong = basic("alice", "wrong");
        assert_eq!(
            check(&auth, &[("Authorization", &wrong)]).await,
            Err("wrong password")
        );
        // Accepted credentials need no bcrypt check, and so no permit, for a while.
        let permits = consumers.checks.permits.clone();
        let all = u32::try_from(permits.available_permits()).unwrap();
        let taken = permits.acquire_many_owned(all).await.unwrap();
        let credentials = basic("alice", "secret");
        let headers = [("Authorization", credentials.as_str())];
        let again = tokio::time::timeout(Duration::from_secs(5), check(&auth, &headers)).await;
        assert_eq!(again, Ok(alice.clone()), "the password was checked again");
        drop(taken);
        // The password is everything after the first colon.
        let carol = basic("carol", "a:b");
        assert_eq!(
            check(&auth, &[("Authorization", &carol)]).await,
            Ok("carol".to_owned())
        );
        for user in ["bob", "dave", "Alice"] {
            let credentials = basic(user, "secret");
            let result = check(&auth, &[("Authorization", &credentials)]).await;
            assert_eq!(result, Err("unknown consumer"), "{user}");
        }
        let no_colon = format!("Basic {}", BASE64.encode("alice"));
        for malformed in ["Basic !!!", &no_colon] {
            let result = check(&auth, &[("Authorization", malformed)]).await;
            assert_eq!(result, Err("malformed Basic credentials"), "{malformed}");
        }
        assert_eq!(check(&auth, &[]).await, Err("no credentials"));
        assert_eq!(
            check(&auth, &[("Authorization", "Bearer a.b.c")]).await,
            Err("no credentials")
        );
        let both = [
            ("X-API-Key", "wrong"),
            ("Authorization", &basic("alice", "secret")),
        ];
        assert_eq!(check(&auth, &both).await, Err("unknown API key"));

        let keys_only = authentication(
            "[routes.api]\nrespond = { status = 204 }\nauth = { api_key = { header = \"X-Token\" } }\n",
            &consumers,
        );
        let basic_alice = basic("alice", "secret");
        let result = check(&keys_only, &[("Authorization", &basic_alice)]).await;
        assert_eq!(result, Err("no credentials"));
        assert_eq!(
            check(&keys_only, &[("X-API-Key", "test")]).await,
            Err("no credentials")
        );
        assert_eq!(check(&keys_only, &[("X-Token", "test")]).await, alice);
    }

    /// Accepted credentials count for five minutes, for the password hash they matched; their
    /// keys depend on a salt of each instance, so they do not give the passwords away.
    #[test]
    fn takes_accepted_passwords_for_a_while() {
        let checks = PasswordChecks::default();
        let key = checks.key(b"alice:secret");
        let now = Instant::now();
        assert!(!checks.accepted(&key, "hash", now));
        checks.accept(key, Arc::from("hash"), now);
        assert!(checks.accepted(&key, "hash", now));
        let later = now + ACCEPTED_FOR - Duration::from_secs(1);
        assert!(checks.accepted(&key, "hash", later));
        assert!(!checks.accepted(&key, "hash", now + ACCEPTED_FOR));
        assert!(!checks.accepted(&key, "new hash", now));
        assert!(!checks.accepted(&checks.key(b"alice:other"), "hash", now));
        assert_ne!(key, PasswordChecks::default().key(b"alice:secret"));
        assert_ne!(key, <[u8; 32]>::from(Sha256::digest(b"alice:secret")));
    }

    /// bcrypt checks wait for a permit, one per CPU core, which they give back when done.
    #[tokio::test]
    async fn bounds_the_password_checks_at_once() {
        let checks = PasswordChecks::default();
        let cores = std::thread::available_parallelism().map_or(1, NonZero::get);
        assert_eq!(checks.permits.available_permits(), cores);
        let hash: Arc<str> = Arc::from(bcrypt::hash("secret", 4).unwrap());
        let taken = checks
            .permits
            .clone()
            .acquire_many_owned(u32::try_from(cores).unwrap())
            .await
            .unwrap();
        let waiting = checks.verify(b"secret".to_vec(), hash.clone());
        let waited = tokio::time::timeout(Duration::from_millis(200), waiting).await;
        assert!(waited.is_err(), "the check ran without a permit");
        drop(taken);
        assert_eq!(
            checks.verify(b"secret".to_vec(), hash.clone()).await,
            Ok(true)
        );
        assert_eq!(checks.verify(b"wrong".to_vec(), hash).await, Ok(false));
        assert_eq!(checks.permits.available_permits(), cores);
    }

    /// Writes the public key of a new P-256 key pair to `file` in `dir`, and returns the key
    /// that signs.
    fn ec_key(dir: &Path, file: &str) -> EncodingKey {
        let pair = rcgen::KeyPair::generate().unwrap();
        std::fs::write(dir.join(file), pair.public_key_pem()).unwrap();
        EncodingKey::from_ec_pem(pair.serialize_pem().as_bytes()).unwrap()
    }

    /// A token with `claims`, signed with `key` by `algorithm`.
    fn token(algorithm: Algorithm, key: &EncodingKey, claims: &Value) -> String {
        jsonwebtoken::encode(&Header::new(algorithm), claims, key).unwrap()
    }

    /// The time in seconds since the epoch, `offset` seconds from now.
    fn at(offset: i64) -> i64 {
        i64::try_from(jsonwebtoken::get_current_timestamp()).unwrap() + offset
    }

    /// Tokens pass with a good signature and good claims, and the consumer comes from the
    /// claim of the settings. Settings with an issuer or audiences need tokens that name one;
    /// settings without audiences take tokens for any.
    #[tokio::test]
    async fn checks_jwts() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ec_key(dir.path(), "jwt.pub");
        let stranger = ec_key(dir.path(), "other.pub");
        std::fs::write(
            dir.path().join("secret"),
            "a shared secret of 32 bytes or more\n",
        )
        .unwrap();
        let consumers = consumers(
            r#"
            [jwt.main]
            algorithm = "ES256"
            public_key = "jwt.pub"
            issuer = "https://auth.example.com"
            audience = ["api", "admin"]
            [jwt.open]
            algorithm = "HS256"
            secret = { file = "secret" }
            consumer_claim = "client_id"
            "#,
            dir.path(),
        )
        .await;
        let main = &consumers.jwt["main"];
        let valid = json!({
            "sub": "alice", "iss": "https://auth.example.com", "aud": "api", "exp": at(3600)
        });
        let check =
            |claims: &Value| main.consumer(token(Algorithm::ES256, &signer, claims).as_bytes());
        let with = |claim: &str, value: Value| {
            let mut claims = valid.clone();
            claims[claim] = value;
            claims
        };
        let without = |claim: &str| {
            let mut claims = valid.clone();
            claims.as_object_mut().unwrap().remove(claim);
            claims
        };
        let alice = Ok("alice".to_owned());
        assert_eq!(check(&valid), alice);
        assert_eq!(check(&with("aud", json!(["other", "admin"]))), alice);
        // Clocks may be a minute apart.
        assert_eq!(check(&with("exp", json!(at(-30)))), alice);
        assert_eq!(check(&with("nbf", json!(at(30)))), alice);
        assert_eq!(check(&with("exp", json!(at(-3600)))), Err("token expired"));
        assert_eq!(
            check(&with("nbf", json!(at(3600)))),
            Err("token not valid yet")
        );
        let evil = with("iss", json!("https://evil.example.com"));
        assert_eq!(check(&evil), Err("token from another issuer"));
        assert_eq!(
            check(&with("aud", json!(["other"]))),
            Err("token for another audience")
        );
        for claim in ["aud", "iss", "exp"] {
            assert_eq!(
                check(&without(claim)),
                Err("token without a required claim"),
                "{claim}"
            );
        }
        assert_eq!(
            check(&without("sub")),
            Err("token without its consumer claim")
        );
        assert_eq!(check(&with("sub", json!(42))), Ok("42".to_owned()));
        for consumer in ["", "a\nb"] {
            let claims = with("sub", json!(consumer));
            let refused = Err("token with a consumer that cannot be a header value");
            assert_eq!(check(&claims), refused, "{consumer:?}");
        }

        // Another key, another algorithm with the public key as the secret, or none at all.
        let forged = token(Algorithm::ES256, &stranger, &valid);
        assert_eq!(
            main.consumer(forged.as_bytes()),
            Err("token with a wrong signature")
        );
        let public = std::fs::read(dir.path().join("jwt.pub")).unwrap();
        let confused = token(Algorithm::HS256, &EncodingKey::from_secret(&public), &valid);
        let refused = Err("token signed with another algorithm");
        assert_eq!(main.consumer(confused.as_bytes()), refused);
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(valid.to_string())
        );
        assert_eq!(main.consumer(unsigned.as_bytes()), Err("malformed token"));
        assert_eq!(main.consumer(b"not a token"), Err("malformed token"));

        let open = &consumers.jwt["open"];
        let secret = EncodingKey::from_secret(b"a shared secret of 32 bytes or more");
        let claims = json!({ "client_id": "billing", "aud": "elsewhere", "exp": at(60) });
        let billing = token(Algorithm::HS256, &secret, &claims);
        assert_eq!(open.consumer(billing.as_bytes()), Ok("billing".to_owned()));
        let claims = json!({ "client_id": { "id": 42 }, "exp": at(60) });
        let object = token(Algorithm::HS256, &secret, &claims);
        let refused = Err("token without its consumer claim");
        assert_eq!(open.consumer(object.as_bytes()), refused);
    }

    /// Keys and secrets that cannot be read reject the configuration, at their setting.
    #[tokio::test]
    async fn rejects_unreadable_keys() {
        let dir = tempfile::tempdir().unwrap();
        ec_key(dir.path(), "ec.pub");
        std::fs::write(dir.path().join("garbage.pub"), "not a key").unwrap();
        let config = parse(
            r#"
            [jwt.garbage]
            algorithm = "ES256"
            public_key = "garbage.pub"
            [jwt.missing]
            algorithm = "EdDSA"
            public_key = "missing.pub"
            [jwt.unset]
            algorithm = "HS512"
            secret = { env = "WORMWAY_TEST_SURELY_UNSET" }
            [jwt.wrong-kind]
            algorithm = "RS256"
            public_key = "ec.pub"
            [jwt.good]
            algorithm = "ES256"
            public_key = "ec.pub"
            "#,
        );
        let issues = Consumers::load(&config, dir.path(), Arc::default())
            .await
            .err()
            .unwrap();
        let paths: Vec<&str> = issues.iter().map(|issue| issue.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "jwt.garbage.public_key",
                "jwt.missing.public_key",
                "jwt.unset.secret",
                "jwt.wrong-kind.public_key",
            ]
        );
        assert!(
            issues[0].message.contains("holds no EC public key in PEM"),
            "{issues:?}"
        );
        assert!(issues[1].message.starts_with("cannot read "), "{issues:?}");
        let unset = "environment variable WORMWAY_TEST_SURELY_UNSET is not set";
        assert_eq!(issues[2].message, unset);
        assert!(
            issues[3].message.contains("holds no RSA public key in PEM"),
            "{issues:?}"
        );
    }

    /// 401 answers name each way that the route takes, in the order they are looked for; the
    /// consumers of the route are the only ones it lets through, unless it lists none.
    #[tokio::test]
    async fn challenges_and_allows_consumers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret"), "a shared secret").unwrap();
        let jwt = "[jwt.main]\nalgorithm = \"HS256\"\nsecret = { file = \"secret\" }\n";
        let consumers = consumers(jwt, dir.path()).await;
        let route = "[routes.api]\nrespond = { status = 204 }\n";
        let all = authentication(
            &format!(
                "{route}auth = {{ basic = true, api_key = {{ header = \"X-Token\" }}, jwt = \"main\", consumers = [\"alice\", \"auth0|42\"] }}\n{jwt}"
            ),
            &consumers,
        );
        let challenges: Vec<&str> = all
            .challenges
            .iter()
            .map(|challenge| challenge.to_str().unwrap())
            .collect();
        assert_eq!(
            challenges,
            [
                "ApiKey header=\"X-Token\"",
                "Bearer realm=\"wormway\"",
                "Basic realm=\"wormway\", charset=\"UTF-8\"",
            ]
        );
        assert!(all.allows("alice") && all.allows("auth0|42"));
        assert!(!all.allows("bob") && !all.allows("Alice"));

        let open = authentication(&format!("{route}auth = {{ api_key = true }}\n"), &consumers);
        assert!(open.allows("anyone"));
        let challenges: Vec<&str> = open
            .challenges
            .iter()
            .map(|challenge| challenge.to_str().unwrap())
            .collect();
        assert_eq!(challenges, ["ApiKey header=\"X-API-Key\""]);
    }
}
