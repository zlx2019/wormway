//! Probes of the active health checks: a TCP connection, or a request that reaches the target
//! the way the requests of its upstream do.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use pingora::ErrorType;
use pingora::connectors::http::Connector;
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use tokio::net::TcpStream;
use wormway_core::config::{HealthCheck, HealthCheckKind};

use crate::listener::panic_message;
use crate::upstream::{Connect, TargetHost};

/// `User-Agent` of the requests of the probes.
const USER_AGENT: &str = "wormway-health-check";

/// Makes the probes of every upstream.
#[derive(Default)]
pub(crate) struct Prober {
    /// Connects the HTTP probes. Created on first use, since it reads the certificate
    /// authorities of the system; it keeps no connection, as every probe makes its own.
    connector: OnceLock<Arc<Connector>>,
}

impl Prober {
    /// Returns the connector of the HTTP probes, created on a blocking thread on first use.
    /// Pingora panics when it cannot read the certificate authorities of the system; that
    /// comes back as an error.
    pub(crate) async fn connector(&self) -> Result<Arc<Connector>, String> {
        if let Some(connector) = self.connector.get() {
            return Ok(connector.clone());
        }
        let created = tokio::task::spawn_blocking(|| Arc::new(Connector::new(None)))
            .await
            .map_err(|error| {
                let reason = match error.try_into_panic() {
                    Ok(panic) => panic_message(&*panic).to_owned(),
                    Err(error) => error.to_string(),
                };
                format!("cannot set up the connections of the health checks: {reason}")
            })?;
        Ok(self.connector.get_or_init(|| created).clone())
    }

    /// Probes `target`, reached through `connect`, as `check` asks. The error says why the
    /// probe failed.
    pub(crate) async fn probe(
        &self,
        check: &HealthCheck,
        connect: &Connect,
        target: &Backend,
    ) -> Result<(), String> {
        let probe = async {
            match check.kind {
                HealthCheckKind::Tcp => tcp(target).await,
                HealthCheckKind::Http => self.http(check, connect, target).await,
            }
        };
        tokio::time::timeout(check.timeout().get(), probe)
            .await
            .unwrap_or_else(|_| Err(format!("no answer within {}", check.timeout())))
    }

    /// Sends `GET` to `target` over a new connection and reads the whole response: its status
    /// must pass.
    async fn http(
        &self,
        check: &HealthCheck,
        connect: &Connect,
        target: &Backend,
    ) -> Result<(), String> {
        let connector = self.connector().await?;
        let mut peer = connect.peer(target);
        // One stream per HTTP/2 connection keeps the connection out of the pool, so it closes
        // with the probe, as HTTP/1.1 connections that are not handed back do.
        peer.options.max_h2_streams = 1;
        let (mut session, _) = connector
            .get_http_session(&peer)
            .await
            .map_err(|error| describe(&error))?;
        let mut request = RequestHeader::build("GET", check.path().as_bytes(), None)
            .map_err(|error| describe(&error))?;
        request
            .insert_header("Host", host(check, connect, target))
            .and_then(|()| request.insert_header("User-Agent", USER_AGENT))
            .map_err(|error| describe(&error))?;
        session
            .write_request_header(Box::new(request))
            .await
            .map_err(|error| describe(&error))?;
        session
            .finish_request_body()
            .await
            .map_err(|error| describe(&error))?;
        session
            .read_response_header()
            .await
            .map_err(|error| describe(&error))?;
        let status = session
            .response_header()
            .map_or(0, |response| response.status.as_u16());
        if !check.passes(status) {
            return Err(format!("status {status}"));
        }
        while session
            .read_response_body()
            .await
            .map_err(|error| describe(&error))?
            .is_some()
        {}
        Ok(())
    }
}

/// Connects to `target` over TCP.
async fn tcp(target: &Backend) -> Result<(), String> {
    let Some(address) = target.addr.as_inet() else {
        return Err("not an IP address".to_owned());
    };
    match TcpStream::connect(address).await {
        Ok(_) => Ok(()),
        Err(error) => Err(describe_io(&error)),
    }
}

/// Returns the `Host` header of a probe of `target`: the one of `check`, or the configured
/// name of TLS, the host name of the target or its IP address, with the port unless it is the
/// default one of the scheme.
fn host(check: &HealthCheck, connect: &Connect, target: &Backend) -> String {
    if let Some(host) = &check.host {
        return host.clone();
    }
    let Some(address) = target.addr.as_inet() else {
        return String::new();
    };
    let name = match (connect.sni(), target.ext.get::<TargetHost>()) {
        (Some(sni), _) => sni.to_owned(),
        (None, Some(TargetHost(host))) => host.to_string(),
        (None, None) => address.ip().to_string(),
    };
    // Only IPv6 addresses hold colons, and they go in brackets.
    let name = match name.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{name}]"),
        _ => name,
    };
    let default_port = if connect.tls() { 443 } else { 80 };
    if address.port() == default_port {
        name
    } else {
        format!("{name}:{}", address.port())
    }
}

/// Returns what went wrong in `error` in a few words, for the log: its kind, and its root cause
/// when the kind does not say it all.
pub(crate) fn describe(error: &pingora::Error) -> String {
    let what = match error.etype() {
        ErrorType::ConnectTimedout => return "connecting timed out".to_owned(),
        ErrorType::ConnectRefused => return "connection refused".to_owned(),
        ErrorType::ConnectNoRoute => return "no route to the target".to_owned(),
        ErrorType::TLSHandshakeTimedout => return "TLS handshake timed out".to_owned(),
        ErrorType::ReadTimedout => return "no answer in time".to_owned(),
        ErrorType::WriteTimedout => return "sending timed out".to_owned(),
        ErrorType::ConnectionClosed => return "connection closed".to_owned(),
        ErrorType::TLSHandshakeFailure | ErrorType::HandshakeError => "TLS handshake failed",
        ErrorType::InvalidCert => "invalid certificate",
        ErrorType::ConnectError => "cannot connect",
        ErrorType::ReadError => "reading failed",
        ErrorType::WriteError => "sending failed",
        other => other.as_str(),
    };
    let root = error.root_cause();
    let own = root.downcast_ref::<pingora::Error>().is_some()
        || root.downcast_ref::<Box<pingora::Error>>().is_some();
    if own {
        what.to_owned()
    } else {
        format!("{what}: {root}")
    }
}

/// Returns what went wrong in `error` in a few words.
fn describe_io(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::Other => error.to_string(),
        kind => kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use wormway_core::config::UpstreamProtocol;

    use super::*;

    /// A check of `kind` with the defaults.
    fn check(kind: HealthCheckKind) -> HealthCheck {
        HealthCheck {
            kind,
            path: None,
            host: None,
            status: None,
            interval: None,
            timeout: None,
            healthy: None,
            unhealthy: None,
        }
    }

    /// The target at `address`, resolved from `host` if set.
    fn target(address: &str, host: Option<&str>) -> Backend {
        let mut target = Backend::new(address).unwrap();
        if let Some(host) = host {
            target.ext.insert(TargetHost(host.into()));
        }
        target
    }

    /// The host header names the target as requests would, with the port unless it is the
    /// default one; a configured host wins.
    #[test]
    fn names_the_target_in_the_host_header() {
        let plain = Connect::new(UpstreamProtocol::H1, None);
        let http = check(HealthCheckKind::Http);
        assert_eq!(
            host(&http, &plain, &target("10.0.0.1:80", None)),
            "10.0.0.1"
        );
        assert_eq!(
            host(
                &http,
                &plain,
                &target("10.0.0.1:8080", Some("api.internal"))
            ),
            "api.internal:8080"
        );
        assert_eq!(
            host(&http, &plain, &target("[::1]:8080", None)),
            "[::1]:8080"
        );
        let mut named = check(HealthCheckKind::Http);
        named.host = Some("status.internal".to_owned());
        assert_eq!(
            host(&named, &plain, &target("10.0.0.1:8080", None)),
            "status.internal"
        );
    }

    /// A TCP probe of a closed port fails at once, and one of an open port passes.
    #[tokio::test]
    async fn connects_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().to_string();
        let closed = {
            let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            gone.local_addr().unwrap().to_string()
        };
        let prober = Prober::default();
        let tcp = check(HealthCheckKind::Tcp);
        let plain = Connect::new(UpstreamProtocol::H1, None);
        let passed = prober.probe(&tcp, &plain, &target(&open, None)).await;
        assert_eq!(passed, Ok(()));
        let failed = prober.probe(&tcp, &plain, &target(&closed, None)).await;
        assert_eq!(failed, Err("connection refused".to_owned()));
    }
}
