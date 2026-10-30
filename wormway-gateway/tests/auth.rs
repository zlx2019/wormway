//! Integration tests of the authentication of routes: API keys, Basic authentication and JWTs,
//! the consumers that routes let through, and what the upstream and the access log learn.

#[allow(
    dead_code,
    reason = "these tests start their servers with an access log"
)]
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::extract::Request;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use wormway_core::config::{AccessLogFormat, AccessLogSettings};
use wormway_core::time::LogTime;
use wormway_gateway::AccessLog;

use crate::common::{addr, serve, start_logged};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// The SHA-256 of `alice-key` and of `bob-key`.
const KEYS: [&str; 2] = [
    "sha256:72ee9d4355ccb9d3a4c9dbf37382e38e75c1b1a225b5bd1f729ee91bbda30c20",
    "sha256:9b94dc1a51a38769f135edf04033ad7f2f487b6c25929be7a861cfc1ab10cf98",
];

/// The shared secret of the JWT settings.
const SECRET: &str = "a shared secret for the tokens of the tests";

/// Starts an upstream that answers with the `X-Consumer` header of each request, `-` without.
async fn consumer_upstream() -> SocketAddr {
    serve(axum::Router::new().fallback(|request: Request| async move {
        request
            .headers()
            .get("x-consumer")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    }))
    .await
}

/// A client that ignores the proxy settings of the environment and gives up after [`LIMIT`].
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .expect("client")
}

/// What came back for a request.
#[derive(Debug, PartialEq)]
struct Answer {
    /// The status.
    status: u16,
    /// The body: the consumer that the upstream learned.
    body: String,
    /// The `WWW-Authenticate` values.
    challenges: Vec<String>,
}

/// Sends `GET path` to `web` with `headers`.
async fn get(web: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Answer {
    let mut request = client().get(format!("http://{web}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.expect("send");
    let challenges = response
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|value| value.to_str().expect("text").to_owned())
        .collect();
    Answer {
        status: response.status().as_u16(),
        challenges,
        body: response.text().await.expect("body"),
    }
}

/// An answer of the upstream with `consumer`.
fn passed(consumer: &str) -> Answer {
    Answer {
        status: 200,
        body: consumer.to_owned(),
        challenges: Vec::new(),
    }
}

/// An answer of Wormway with `status` and `challenges`.
fn refused(status: u16, challenges: &[&str]) -> Answer {
    Answer {
        status,
        body: String::new(),
        challenges: challenges
            .iter()
            .map(|challenge| (*challenge).to_owned())
            .collect(),
    }
}

/// The `Authorization` value of a token for `subject`, signed with [`SECRET`].
fn bearer(subject: &str) -> String {
    let expires = jsonwebtoken::get_current_timestamp() + 3600;
    let claims = serde_json::json!({ "sub": subject, "exp": expires });
    let key = EncodingKey::from_secret(SECRET.as_bytes());
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key).expect("token");
    format!("Bearer {token}")
}

/// The `Authorization` value of Basic credentials `user` and `password`.
fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

/// Waits up to [`LIMIT`] for `count` lines in the access log at `path`, and returns them.
async fn logged(path: &Path, count: usize) -> String {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.lines().count() >= count {
            return text;
        }
        assert!(tokio::time::Instant::now() < deadline, "{text}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Each route takes the credentials it asks for and passes their consumer to the upstream in
/// `X-Consumer`, which clients cannot set themselves; others get 401 with the ways to
/// authenticate and the headers of the route, consumers that the route leaves out 403. A rate
/// limit by consumer counts after the authentication. The access log names the consumer and
/// tells why requests were turned away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticates_consumers() {
    let dir = tempfile::tempdir().expect("directory");
    let (log, secret) = (dir.path().join("access.log"), dir.path().join("secret"));
    std::fs::write(&secret, SECRET).expect("write the secret");
    let hash = bcrypt::hash("secret", 4).expect("hash");
    let app = consumer_upstream().await;
    let [alice_key, bob_key] = KEYS;
    let config = format!(
        r#"
        [listeners.web]
        listen = ["127.0.0.1:0"]
        protocol = "http"
        [routes.keys]
        match = {{ paths = ["/keys"] }}
        upstream = "app"
        auth = {{ api_key = true }}
        response_headers = {{ set = {{ "Access-Control-Allow-Origin" = "*" }} }}
        [routes.members]
        match = {{ paths = ["/members"] }}
        upstream = "app"
        auth = {{ api_key = true, basic = true, consumers = ["alice"] }}
        [routes.tokens]
        match = {{ paths = ["/tokens"] }}
        upstream = "app"
        auth = {{ jwt = "main" }}
        rate_limit = {{ requests = 1, per = "1m", key = "consumer" }}
        [routes.open]
        match = {{ paths = ["/open"] }}
        upstream = "app"
        [upstreams.app]
        targets = ["{app}"]
        [consumers.alice]
        password_hash = "{hash}"
        api_keys = ["{alice_key}"]
        [consumers.bob]
        api_keys = ["{bob_key}"]
        [jwt.main]
        algorithm = "HS256"
        secret = {{ file = "secret" }}
        "#
    );
    let settings = AccessLogSettings {
        format: AccessLogFormat::Json,
        path: Some(log.clone()),
    };
    let access_log =
        AccessLog::open(&settings, LogTime::default(), Path::new(".")).expect("access log");
    // Files of the configuration, such as the secret, are relative to the directory.
    let server = start_logged(&config, dir.path(), Some(access_log)).await;
    let web = addr(&server, "web").await;

    let api_key = "ApiKey header=\"X-API-Key\"";
    let missing = get(web, "/keys", &[]).await;
    assert_eq!(missing, refused(401, &[api_key]));
    let spoofed = [("X-API-Key", "alice-key"), ("X-Consumer", "mallory")];
    assert_eq!(get(web, "/keys", &spoofed).await, passed("alice"));
    assert_eq!(
        get(web, "/keys", &[("X-API-Key", "bob-key")]).await,
        passed("bob")
    );
    let response = client()
        .get(format!("http://{web}/keys"))
        .header("X-API-Key", "wrong")
        .send()
        .await
        .expect("send");
    assert_eq!(response.status().as_u16(), 401);
    let origin = response.headers().get("access-control-allow-origin");
    assert_eq!(origin.and_then(|value| value.to_str().ok()), Some("*"));

    let basic_realm = "Basic realm=\"wormway\", charset=\"UTF-8\"";
    let alice = basic("alice", "secret");
    assert_eq!(
        get(web, "/members", &[("Authorization", &alice)]).await,
        passed("alice")
    );
    let wrong = basic("alice", "wrong");
    let refused_basic = refused(401, &[api_key, basic_realm]);
    assert_eq!(
        get(web, "/members", &[("Authorization", &wrong)]).await,
        refused_basic
    );
    assert_eq!(
        get(web, "/members", &[("X-API-Key", "bob-key")]).await,
        refused(403, &[])
    );

    let carol = bearer("carol");
    assert_eq!(
        get(web, "/tokens", &[("Authorization", &carol)]).await,
        passed("carol")
    );
    let limited = get(web, "/tokens", &[("Authorization", &carol)]).await;
    assert_eq!(limited.status, 429);
    let dave = bearer("dave");
    assert_eq!(
        get(web, "/tokens", &[("Authorization", &dave)]).await,
        passed("dave")
    );
    let bearer_realm = refused(401, &["Bearer realm=\"wormway\""]);
    assert_eq!(
        get(web, "/tokens", &[("Authorization", &alice)]).await,
        bearer_realm
    );

    assert_eq!(
        get(web, "/open", &[("X-Consumer", "mallory")]).await,
        passed("-")
    );

    let lines = logged(&log, 12).await;
    let line = |needle: &str| {
        lines
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle}: {lines}"))
    };
    let unauthorized = line("\"status\":401");
    assert!(unauthorized.contains("\"consumer\":null"), "{unauthorized}");
    assert!(
        unauthorized.contains("\"error\":\"no credentials\""),
        "{unauthorized}"
    );
    let forbidden = line("\"status\":403");
    assert!(forbidden.contains("\"consumer\":\"bob\""), "{forbidden}");
    assert!(
        forbidden.contains("\"error\":\"consumer not allowed\""),
        "{forbidden}"
    );
    assert!(
        line("\"status\":429").contains("\"consumer\":\"carol\""),
        "{lines}"
    );
    let wrong_password = line("\"error\":\"wrong password\"");
    assert!(
        wrong_password.contains("\"status\":401"),
        "{wrong_password}"
    );
}
