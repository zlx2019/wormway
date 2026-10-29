//! A client of the Admin API of a running Wormway, for the `wormway config` commands.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use reqwest::RequestBuilder;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wormway_core::config::{Config, Issue};

use crate::{ADMIN_TOKEN_ENV, load};

/// How long a request may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The Admin API of the Wormway that runs with a given configuration file.
pub struct AdminClient {
    /// HTTP client.
    http: reqwest::Client,
    /// Address of the API, such as `http://127.0.0.1:9872`.
    base: String,
    /// Token sent with every request.
    token: String,
}

/// An error answered by the Admin API.
#[derive(Deserialize)]
pub struct ApiError {
    /// Machine-readable code, such as `invalid_config`.
    pub code: String,
    /// Explanation.
    pub message: String,
    /// Problems with single settings.
    #[serde(default)]
    pub details: Vec<Issue>,
}

/// JSON shape of an error answer.
#[derive(Deserialize)]
struct ErrorBody {
    /// The error.
    error: ApiError,
}

impl AdminClient {
    /// Prepares requests to the Admin API set in `config`, read from the file at `path`. The
    /// token comes from `WORMWAY_ADMIN_TOKEN`, or else from the token file Wormway created.
    pub fn new(path: &Path, config: &Config) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            // The API is usually on loopback; a proxy from the environment would get in the way.
            .no_proxy()
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            base: format!("http://{}", reachable(config.admin.listen)),
            token: token(path, config)?,
        })
    }

    /// `GET path`, answered with JSON.
    pub async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> anyhow::Result<Result<T, ApiError>> {
        self.send(self.http.get(format!("{}{path}", self.base)))
            .await
    }

    /// `PUT path` with `body` as JSON, answered with JSON.
    pub async fn put<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> anyhow::Result<Result<T, ApiError>> {
        self.send(self.http.put(format!("{}{path}", self.base)).json(body))
            .await
    }

    /// Sends `request` with the token and reads the answer. The outer error means Wormway could
    /// not be reached or answered something unreadable, the inner one is the error it answered.
    async fn send<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> anyhow::Result<Result<T, ApiError>> {
        let response = request
            .bearer_auth(&self.token)
            // Versions saved from here are marked as changes from the command line.
            .header("Wormway-Client", "cli")
            .send()
            .await
            .with_context(|| {
                format!(
                    "cannot reach the Admin API at {}, is Wormway running?",
                    self.base
                )
            })?;
        let status = response.status();
        if status.is_success() {
            let answer = response
                .json()
                .await
                .context("unreadable answer from the Admin API")?;
            return Ok(Ok(answer));
        }
        let body: ErrorBody = response
            .json()
            .await
            .with_context(|| format!("the Admin API answered {status}"))?;
        Ok(Err(body.error))
    }
}

/// Where an API that listens on `addr` can be reached: wildcard addresses accept connections
/// on loopback.
fn reachable(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port())
}

/// Returns the token from `WORMWAY_ADMIN_TOKEN`, or else from the token file of `config`, read
/// from the file at `path`. Unlike `wormway run`, it never creates the file.
fn token(path: &Path, config: &Config) -> anyhow::Result<String> {
    if let Ok(token) = std::env::var(ADMIN_TOKEN_ENV) {
        return Ok(token.trim().to_owned());
    }
    let file = load::data_dir(path, config).join(&config.admin.token_file);
    let text = std::fs::read_to_string(&file).with_context(|| {
        format!(
            "cannot read the Admin API token from {}, set {ADMIN_TOKEN_ENV} or start Wormway once to create the file",
            file.display()
        )
    })?;
    Ok(text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wildcard addresses become loopback of the same family; others stay.
    #[test]
    fn reaches_wildcards_on_loopback() {
        let reach = |addr: &str| reachable(addr.parse().unwrap()).to_string();
        assert_eq!(reach("0.0.0.0:9872"), "127.0.0.1:9872");
        assert_eq!(reach("[::]:9872"), "[::1]:9872");
        assert_eq!(reach("192.0.2.1:9872"), "192.0.2.1:9872");
    }
}
