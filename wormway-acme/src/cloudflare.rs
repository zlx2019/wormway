//! The DNS API of Cloudflare, which publishes the TXT records of DNS-01 challenges.

use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};

use crate::{https, reason};

/// Where the API of Cloudflare is.
const API: &str = "https://api.cloudflare.com/client/v4";
/// Longest wait for an answer of the API.
const TIMEOUT: Duration = Duration::from_secs(30);

/// A client of the DNS API of Cloudflare.
pub(crate) struct Cloudflare {
    /// Where the API is.
    api: String,
    /// The API token.
    token: String,
    /// The HTTPS client.
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

/// A DNS record that Wormway added, to delete again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// ID of the zone that holds it.
    zone: String,
    /// ID of the record.
    id: String,
}

impl Cloudflare {
    /// Creates a client of the API that authenticates with `token`.
    pub(crate) fn new(token: &str) -> Result<Self, String> {
        Self::with_api(API, token)
    }

    /// Creates a client of the API at `api`, which may be plain HTTP, authenticating with
    /// `token`. HTTPS certificates are checked the way of the system.
    fn with_api(api: &str, token: &str) -> Result<Self, String> {
        let connector = https::connector(None, true)?;
        Ok(Self {
            api: api.to_owned(),
            token: token.to_owned(),
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// Adds a TXT record `name` with `value` to the zone that holds the name, and returns it.
    pub(crate) async fn add_txt(&self, name: &str, value: &str) -> Result<Record, String> {
        let zone = self.zone_of(name).await?;
        let record = json!({ "type": "TXT", "name": name, "content": value, "ttl": 60 });
        let path = format!("/zones/{zone}/dns_records");
        let added = self.call(Method::POST, &path, Some(&record)).await?;
        let id = added["id"]
            .as_str()
            .ok_or_else(|| "Cloudflare did not tell the ID of the record".to_owned())?;
        Ok(Record {
            zone,
            id: id.to_owned(),
        })
    }

    /// Deletes `record`.
    pub(crate) async fn remove(&self, record: &Record) -> Result<(), String> {
        let path = format!("/zones/{}/dns_records/{}", record.zone, record.id);
        self.call(Method::DELETE, &path, None).await.map(drop)
    }

    /// Returns the ID of the zone that holds `name`: the longest of its parent domains that
    /// the token can see.
    async fn zone_of(&self, name: &str) -> Result<String, String> {
        let mut rest = name;
        while let Some((_, parent)) = rest.split_once('.')
            && parent.contains('.')
        {
            let zones = self
                .call(Method::GET, &format!("/zones?name={parent}"), None)
                .await?;
            let id = zones
                .as_array()
                .and_then(|zones| zones.first()?["id"].as_str());
            if let Some(id) = id {
                return Ok(id.to_owned());
            }
            rest = parent;
        }
        Err(format!(
            "no Cloudflare zone that the API token can see holds {name}"
        ))
    }

    /// Sends `method path` with `body` as JSON, and returns the result of a successful answer.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let body = body.map_or_else(Bytes::new, |body| Bytes::from(body.to_string()));
        let request = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.api))
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .map_err(|error| format!("cannot make the request to Cloudflare: {error}"))?;
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|error| format!("cannot reach Cloudflare: {}", reason(&error)))?;
            let status = response.status();
            let body = response.into_body().collect().await.map_err(|error| {
                format!("cannot read the answer of Cloudflare: {}", reason(&error))
            })?;
            Ok::<_, String>((status, body.to_bytes()))
        };
        let (status, body) = tokio::time::timeout(TIMEOUT, exchange)
            .await
            .map_err(|_| "Cloudflare did not answer in time".to_owned())??;
        let answer: Value = serde_json::from_slice(&body)
            .map_err(|_| format!("Cloudflare answered {status} without JSON"))?;
        if answer["success"] != true {
            let message = answer["errors"][0]["message"]
                .as_str()
                .unwrap_or("no reason given");
            return Err(format!("Cloudflare answered {status}: {message}"));
        }
        Ok(answer["result"].clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{delete, get, post};
    use tokio::net::TcpListener;

    use super::*;

    /// What the fake API saw: the records added and the IDs deleted.
    #[derive(Default)]
    struct Seen {
        /// Bodies of the records added.
        added: Vec<Value>,
        /// IDs of the records deleted.
        deleted: Vec<String>,
    }

    /// The answer of the fake API to a token other than `good-token`.
    fn forbidden() -> (StatusCode, Json<Value>) {
        let errors = json!([{ "code": 9109, "message": "Invalid access token" }]);
        let body = json!({ "success": false, "errors": errors, "result": null });
        (StatusCode::FORBIDDEN, Json(body))
    }

    /// Whether the request carries the token of the fake API.
    fn allowed(headers: &HeaderMap) -> bool {
        headers[AUTHORIZATION] == "Bearer good-token"
    }

    /// Starts a fake API that holds zone `z1` for `example.com`, and returns its address and
    /// what it saw.
    async fn fake_api() -> (String, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let zones = |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
            if !allowed(&headers) {
                return forbidden();
            }
            let zones = match query.get("name").map(String::as_str) {
                Some("example.com") => json!([{ "id": "z1", "name": "example.com" }]),
                _ => json!([]),
            };
            (
                StatusCode::OK,
                Json(json!({ "success": true, "errors": [], "result": zones })),
            )
        };
        let add = |State(seen): State<Arc<Mutex<Seen>>>,
                   Path(zone): Path<String>,
                   Json(record): Json<Value>| async move {
            assert_eq!(zone, "z1");
            seen.lock().unwrap().added.push(record);
            Json(json!({ "success": true, "errors": [], "result": { "id": "r1" } }))
        };
        let remove = |State(seen): State<Arc<Mutex<Seen>>>,
                      Path((zone, id)): Path<(String, String)>| async move {
            assert_eq!(zone, "z1");
            seen.lock().unwrap().deleted.push(id);
            Json(json!({ "success": true, "errors": [], "result": { "id": "r1" } }))
        };
        let app = axum::Router::new()
            .route("/zones", get(zones))
            .route("/zones/{zone}/dns_records", post(add))
            .route("/zones/{zone}/dns_records/{id}", delete(remove))
            .with_state(seen.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    /// A record goes to the zone of the longest parent domain that exists, and is deleted by
    /// its ID; names outside the zones and a wrong token fail with the reason.
    #[tokio::test]
    async fn adds_and_removes_txt_records() {
        let (api, seen) = fake_api().await;
        let cloudflare = Cloudflare::with_api(&api, "good-token").unwrap();
        let name = "_acme-challenge.www.example.com";
        let record = cloudflare.add_txt(name, "digest").await.unwrap();
        assert_eq!(
            seen.lock().unwrap().added,
            [json!({ "type": "TXT", "name": name, "content": "digest", "ttl": 60 })]
        );
        cloudflare.remove(&record).await.unwrap();
        assert_eq!(seen.lock().unwrap().deleted, ["r1"]);

        let elsewhere = cloudflare
            .add_txt("_acme-challenge.example.org", "digest")
            .await;
        assert_eq!(
            elsewhere.unwrap_err(),
            "no Cloudflare zone that the API token can see holds _acme-challenge.example.org"
        );
        let wrong = Cloudflare::with_api(&api, "bad-token").unwrap();
        let refused = wrong.add_txt(name, "digest").await.unwrap_err();
        assert_eq!(
            refused,
            "Cloudflare answered 403 Forbidden: Invalid access token"
        );
    }
}
