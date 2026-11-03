//! The HTTPS connections of ACME and of the DNS provider APIs. They use the crypto of Wormway's
//! TLS, aws-lc-rs with post-quantum key exchange first, whatever the process-wide default of
//! rustls is, and check certificates the way of the system or against given authorities.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use wormway_runtime::BoxError;

/// Longest exchange with the certificate authority: connecting, sending the request and reading
/// the whole answer.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The HTTP client of ACME: hyper, with every exchange limited in time, so that a certificate
/// authority that stops answering cannot hold up the manager, which orders one certificate at a
/// time. A failed exchange fails the order the usual way, which withdraws its answers.
pub(crate) struct AcmeClient {
    /// The HTTPS client.
    client: Client<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>,
    /// Longest exchange.
    timeout: Duration,
}

impl AcmeClient {
    /// Creates the client, which connects through `connector`.
    pub(crate) fn new(connector: HttpsConnector<HttpConnector>) -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            timeout: EXCHANGE_TIMEOUT,
        }
    }
}

impl HttpClient for AcmeClient {
    /// Sends `request` and reads the whole answer, or gives up when the time is over.
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let response = self.client.request(request);
        let timeout = self.timeout;
        Box::pin(async move {
            // instant-acme reads the body later, so it is read here, within the time limit.
            let exchange = async {
                let (parts, body) = response.await?.into_parts();
                let body = body.collect().await?.to_bytes();
                Ok::<_, BoxError>(Response::from_parts(parts, Full::new(body)))
            };
            match tokio::time::timeout(timeout, exchange).await {
                Ok(Ok(response)) => Ok(BytesResponse::from(response)),
                Ok(Err(error)) => Err(Error::Other(error)),
                Err(_) => Err(Error::Other(format!("no answer within {timeout:?}").into())),
            }
        })
    }
}

/// Builds the connector of a client that checks certificates the way of the system, or
/// against `authorities` when given. It connects over plain HTTP too if `plain`, for test
/// servers.
pub(crate) fn connector(
    authorities: Option<Vec<CertificateDer<'static>>>,
    plain: bool,
) -> Result<HttpsConnector<HttpConnector>, String> {
    let provider = wormway_tls::provider();
    let builder = match authorities {
        None => HttpsConnectorBuilder::new()
            .with_provider_and_platform_verifier(provider)
            .map_err(|error| {
                format!("cannot use the certificate authorities of the system: {error}")
            })?,
        Some(authorities) => {
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(authorities);
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| format!("cannot set up TLS: {error}"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpsConnectorBuilder::new().with_tls_config(config)
        }
    };
    let builder = if plain {
        builder.https_or_http()
    } else {
        builder.https_only()
    };
    Ok(builder.enable_http1().build())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Starts a server that reads a request, writes `answer` and then nothing more, keeping the
    /// connection open. Returns its URL.
    async fn server(answer: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    let _ = stream.read(&mut request).await;
                    let _ = stream.write_all(answer).await;
                    std::future::pending::<()>().await;
                });
            }
        });
        format!("http://{addr}/directory")
    }

    /// Sends `GET url` with a client that waits `timeout` at most. The test fails if the client
    /// does not give up by itself within 5 seconds.
    async fn get(url: &str, timeout: Duration) -> Result<BytesResponse, Error> {
        let client = AcmeClient {
            timeout,
            ..AcmeClient::new(connector(None, true).unwrap())
        };
        let request = Request::get(url).body(BodyWrapper::default()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), client.request(request))
            .await
            .expect("the client gave up by itself")
    }

    /// An answer comes back whole. An exchange that stalls, before the head of the answer or
    /// within its body, gives up when the time is over.
    #[tokio::test]
    async fn gives_up_on_stalled_exchanges() {
        let whole = server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let mut answer = get(&whole, Duration::from_secs(5)).await.unwrap();
        assert_eq!(answer.parts.status, 200);
        assert_eq!(answer.body.into_bytes().await.unwrap(), "ok");

        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npart";
        for stalled in [&b""[..], partial] {
            let url = server(stalled).await;
            let started = Instant::now();
            let Err(error) = get(&url, Duration::from_millis(200)).await else {
                panic!("an answer came for {stalled:?}");
            };
            assert_eq!(error.to_string(), "no answer within 200ms");
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }
}
