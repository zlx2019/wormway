//! Integration tests of listeners with TLS: the certificate picked by the host name the client
//! sends, unknown names, HTTP/2 and HTTP/1.1 agreed on through ALPN, h2c, and replaced
//! certificate files.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use wormway_core::config::{AccessLogFormat, AccessLogSettings, ConfigError};
use wormway_gateway::AccessLog;
use wormway_runtime::ApplyError;

use crate::common::{addr, parse, serve, start, start_logged, upstream};

/// A test certificate authority and the directory of the certificate files.
struct Pki {
    /// Directory of the certificate and key files.
    dir: TempDir,
    /// The authority that signs the certificates.
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    /// Creates the authority.
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().expect("CA key");
        Self {
            dir: TempDir::new().expect("directory"),
            ca: CertifiedIssuer::self_signed(params, key).expect("CA certificate"),
        }
    }

    /// Issues a certificate for `names`, writes it and its key as `<file>.crt` and
    /// `<file>.key`, and returns it.
    fn issue(&self, file: &str, names: &[&str]) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("key");
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let cert = CertificateParams::new(names)
            .expect("parameters")
            .signed_by(&key, &*self.ca)
            .expect("certificate");
        let path = |extension: &str| self.dir.path().join(format!("{file}.{extension}"));
        std::fs::write(path("crt"), cert.pem()).expect("write the certificate");
        std::fs::write(path("key"), key.serialize_pem()).expect("write the key");
        cert.der().clone()
    }

    /// A client that trusts this authority only and offers `alpn`.
    fn client(&self, alpn: &[&[u8]]) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.der().clone()).expect("root certificate");
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        connector(config, alpn)
    }
}

/// The crypto provider of the test clients.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Wraps `config` into a connector that offers `alpn`.
fn connector(mut config: ClientConfig, alpn: &[&[u8]]) -> TlsConnector {
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Accepts any certificate, so that tests see which one the server presents.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    /// Accepts the certificate without looking at it.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Checks the handshake signature, which the key of the certificate made.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    /// Checks the handshake signature, which the key of the certificate made.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    /// The schemes of the provider.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client that accepts any certificate and offers HTTP/1.1.
fn any_certificate() -> TlsConnector {
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider())))
        .with_no_client_auth();
    connector(config, &[b"http/1.1"])
}

/// Connects to `addr` with TLS, sending `sni` as the host name, or none.
async fn connect(
    client: &TlsConnector,
    addr: SocketAddr,
    sni: Option<&str>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = match sni {
        Some(name) => ServerName::try_from(name.to_owned()).expect("host name"),
        // rustls sends no host name when it connects to an IP address.
        None => ServerName::IpAddress(addr.ip().into()),
    };
    client.connect(name, tcp).await
}

/// Returns the certificate the server at `addr` presents for `sni`, or `None` if it fails the
/// handshake.
async fn presented(addr: SocketAddr, sni: Option<&str>) -> Option<CertificateDer<'static>> {
    let stream = connect(&any_certificate(), addr, sni).await.ok()?;
    let chain = stream.get_ref().1.peer_certificates()?;
    chain.first().map(|leaf| leaf.clone().into_owned())
}

/// Sends `GET path` over HTTP/1.1 and returns the status and the body.
async fn get_http1(stream: impl AsyncRead + AsyncWrite + Unpin, path: &str) -> (u16, String) {
    let mut stream = BufReader::new(stream);
    let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n");
    stream
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .expect("write");
    let mut line = String::new();
    stream.read_line(&mut line).await.expect("status line");
    let status = line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    let mut headers = HashMap::new();
    loop {
        line.clear();
        stream.read_line(&mut line).await.expect("header");
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length: usize = headers["content-length"].parse().expect("content-length");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.expect("body");
    (status, String::from_utf8(body).expect("UTF-8 body"))
}

/// Sends `GET <scheme>://test<path>` over HTTP/2 and returns the status and the body.
async fn get_http2(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    scheme: &str,
    path: &str,
) -> Result<(u16, String), h2::Error> {
    let (client, connection) = h2::client::handshake(stream).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = axum::http::Request::get(format!("{scheme}://test{path}"))
        .body(())
        .expect("request");
    let (response, _) = client.ready().await?.send_request(request, true)?;
    let (head, mut body) = response.await?.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    Ok((
        head.status.as_u16(),
        String::from_utf8(bytes).expect("UTF-8 body"),
    ))
}

/// A listener `secure` with TLS settings `tls`, the certificates `certificates` from files of
/// the same name, and a route to `target`.
fn config(tls: &str, certificates: &[&str], target: SocketAddr) -> String {
    let mut text = format!(
        "[listeners.secure]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\ntls = {tls}\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{target}\"]\n"
    );
    for name in certificates {
        text += &format!("[certificates.{name}]\ncert = \"{name}.crt\"\nkey = \"{name}.key\"\n");
    }
    text
}

/// Upstreams learn from `X-Forwarded-Proto` that the client came over TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tells_upstreams_about_tls() {
    let pki = Pki::new();
    pki.issue("a", &["a.test"]);
    let proto = serve(
        axum::Router::new().fallback(|headers: axum::http::HeaderMap| async move {
            let proto = headers.get("x-forwarded-proto");
            proto
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-")
                .to_owned()
        }),
    )
    .await;
    let text = config(r#"{ certificates = ["a"] }"#, &["a"], proto);
    let server = start(&text, pki.dir.path()).await;
    let secure = addr(&server, "secure").await;
    let stream = connect(&pki.client(&[b"http/1.1"]), secure, Some("a.test"))
        .await
        .expect("handshake");
    assert_eq!(get_http1(stream, "/").await, (200, "https".to_owned()));
}

/// An exact name, one label under a wildcard, and the first certificate for unknown names and
/// for clients that send none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn picks_certificates_by_host_name() {
    let pki = Pki::new();
    let a = pki.issue("a", &["a.test"]);
    let wild = pki.issue("wild", &["*.b.test"]);
    let tls = r#"{ certificates = ["a", "wild"] }"#;
    let text = config(tls, &["a", "wild"], upstream("app").await);
    let server = start(&text, pki.dir.path()).await;
    let secure = addr(&server, "secure").await;

    assert_eq!(presented(secure, Some("a.test")).await, Some(a.clone()));
    assert_eq!(presented(secure, Some("x.b.test")).await, Some(wild));
    assert_eq!(presented(secure, Some("y.x.b.test")).await, Some(a.clone()));
    assert_eq!(presented(secure, Some("other.test")).await, Some(a.clone()));
    assert_eq!(presented(secure, None).await, Some(a));
}

/// With `unknown_sni = "reject"`, only clients that send a covered name complete the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_unknown_names_when_asked() {
    let pki = Pki::new();
    let a = pki.issue("a", &["a.test"]);
    let tls = r#"{ certificates = ["a"], unknown_sni = "reject" }"#;
    let server = start(&config(tls, &["a"], upstream("app").await), pki.dir.path()).await;
    let secure = addr(&server, "secure").await;

    assert_eq!(presented(secure, Some("a.test")).await, Some(a));
    assert_eq!(presented(secure, Some("other.test")).await, None);
    assert_eq!(presented(secure, None).await, None);
}

/// A client that verifies the certificate gets HTTP/2 when it offers it and HTTP/1.1
/// otherwise, and both reach the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agrees_on_http2_or_http1_through_alpn() {
    let pki = Pki::new();
    pki.issue("a", &["a.test"]);
    let text = config(r#"{ certificates = ["a"] }"#, &["a"], upstream("app").await);
    let server = start(&text, pki.dir.path()).await;
    let secure = addr(&server, "secure").await;

    let both = pki.client(&[b"h2", b"http/1.1"]);
    let stream = connect(&both, secure, Some("a.test"))
        .await
        .expect("handshake");
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (status, body) = get_http2(stream, "https", "/over-h2")
        .await
        .expect("HTTP/2");
    assert_eq!(status, 200);
    assert!(
        body.starts_with("app ") && body.ends_with(" /over-h2"),
        "{body}"
    );

    let http1 = pki.client(&[b"http/1.1"]);
    let stream = connect(&http1, secure, Some("a.test"))
        .await
        .expect("handshake");
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(
        get_http1(stream, "/over-h1").await,
        (200, "app test /over-h1".to_owned())
    );
}

/// The access log tells the TLS version and the HTTP version of requests over TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_the_tls_and_http_versions() {
    let pki = Pki::new();
    pki.issue("a", &["a.test"]);
    let text = config(r#"{ certificates = ["a"] }"#, &["a"], upstream("app").await);
    let log = pki.dir.path().join("access.log");
    let settings = AccessLogSettings {
        format: AccessLogFormat::Json,
        path: Some(log.clone()),
    };
    let access_log = AccessLog::open(&settings, Path::new(".")).expect("open the access log");
    let server = start_logged(&text, pki.dir.path(), Some(access_log)).await;
    let secure = addr(&server, "secure").await;

    let stream = connect(&pki.client(&[b"h2"]), secure, Some("a.test"))
        .await
        .expect("handshake");
    let (status, _) = get_http2(stream, "https", "/logged").await.expect("HTTP/2");
    assert_eq!(status, 200);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let line = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(line) = text.lines().next() {
            break line.to_owned();
        }
        assert!(tokio::time::Instant::now() < deadline, "no line logged");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    for part in [
        r#""host":"test","uri":"/logged","protocol":"HTTP/2.0","status":200"#,
        r#""tls":"TLSv1.3""#,
    ] {
        assert!(line.contains(part), "{part} not in {line}");
    }
}

/// A listener without TLS speaks HTTP/2 to clients that start with it only when h2c is on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_h2c_when_enabled() {
    let target = upstream("app").await;
    let server = start(
        &format!(
            "[listeners.h2c]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\nhttp = {{ h2c = true }}\n[listeners.h1]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{target}\"]\n"
        ),
        std::path::Path::new("."),
    )
    .await;

    let h2c = TcpStream::connect(addr(&server, "h2c").await)
        .await
        .expect("connect");
    let (status, _) = get_http2(h2c, "http", "/").await.expect("h2c");
    assert_eq!(status, 200);
    let h1 = TcpStream::connect(addr(&server, "h1").await)
        .await
        .expect("connect");
    assert!(get_http2(h1, "http", "/").await.is_err());
    let h1 = TcpStream::connect(addr(&server, "h1").await)
        .await
        .expect("connect");
    assert_eq!(get_http1(h1, "/").await.0, 200);
}

/// Replaced certificate files take effect when the configuration is applied again, and
/// unusable files leave the certificates in effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reloads_replaced_certificate_files() {
    let pki = Pki::new();
    let first = pki.issue("a", &["a.test"]);
    let text = config(r#"{ certificates = ["a"] }"#, &["a"], upstream("app").await);
    let server = start(&text, pki.dir.path()).await;
    let secure = addr(&server, "secure").await;
    assert_eq!(presented(secure, Some("a.test")).await, Some(first));

    let second = pki.issue("a", &["a.test"]);
    server.apply(parse(&text)).await.expect("apply");
    assert_eq!(
        presented(secure, Some("a.test")).await,
        Some(second.clone())
    );

    std::fs::remove_file(pki.dir.path().join("a.key")).expect("remove the key");
    match server.apply(parse(&text)).await {
        Err(ApplyError::Config(ConfigError::Invalid(issues))) => {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].path, "certificates.a.key");
            assert!(
                issues[0].message.starts_with("cannot read"),
                "{}",
                issues[0]
            );
        }
        other => panic!("expected an unreadable key, got {other:?}"),
    }
    assert_eq!(presented(secure, Some("a.test")).await, Some(second));
}

/// Each listener presents its own certificates only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presents_the_certificates_of_each_listener() {
    let pki = Pki::new();
    let a = pki.issue("a", &["a.test"]);
    let b = pki.issue("b", &["b.test"]);
    let text = format!(
        "{}[listeners.other]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\ntls = {{ certificates = [\"b\"], unknown_sni = \"reject\" }}\n",
        config(
            r#"{ certificates = ["a"] }"#,
            &["a", "b"],
            upstream("app").await
        )
    );
    let server = start(&text, pki.dir.path()).await;
    let secure = addr(&server, "secure").await;
    let other = addr(&server, "other").await;

    assert_eq!(presented(secure, Some("b.test")).await, Some(a));
    assert_eq!(presented(other, Some("b.test")).await, Some(b));
    assert_eq!(presented(other, Some("a.test")).await, None);
}
