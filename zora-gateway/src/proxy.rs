//! The Pingora application of an HTTP listener: finds the route of each request, then forwards
//! the request to the upstream of the route or answers it, with the changes the route asks for.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::HeaderValue;
use pingora::http::{HMap, Method, RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, HTTPStatus};
use zora_core::config::{Name, Rewrite};
use zora_core::routing::{self, Request, RequestHeaders};

use crate::compress;
use crate::headers::{self, HeaderEdits, RequestId};
use crate::route::{CompiledRoute, FixedResponse, Handler, RedirectTarget};
use crate::snapshot::GatewaySnapshot;

/// Serves the requests of one listener.
pub(crate) struct Proxy {
    /// The listener.
    listener: Name,
    /// Routes and upstreams in effect.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Seconds a kept-alive HTTP/1.1 connection waits for its next request; `None` turns
    /// keep-alive off.
    keepalive: Option<u64>,
    /// Whether the listener has TLS, for `X-Forwarded-Proto`.
    tls: bool,
}

/// State of one request.
pub(crate) struct RequestContext {
    /// Routes and upstreams when the request started, kept until it ends.
    snapshot: Arc<GatewaySnapshot>,
    /// Route of the request, once found.
    route: Option<Arc<CompiledRoute>>,
    /// ID of the request, sent to the upstream as `X-Request-Id`.
    request_id: RequestId,
}

impl Proxy {
    /// Creates the application of `listener`, which has TLS if `tls`.
    pub(crate) fn new(
        listener: Name,
        snapshot: Arc<ArcSwap<GatewaySnapshot>>,
        keepalive: Option<u64>,
        tls: bool,
    ) -> Self {
        Self {
            listener,
            snapshot,
            keepalive,
            tls,
        }
    }

    /// Finds the route of `request` in `snapshot`, by its normalized path.
    fn find_route(
        &self,
        request: &RequestHeader,
        snapshot: &GatewaySnapshot,
    ) -> Option<Arc<CompiledRoute>> {
        let path = routing::normalize_path(request.uri.path().as_bytes());
        let request = Request {
            host: request_host(request),
            path: &path,
            method: request.method.as_str(),
            headers: &Headers(&request.headers),
        };
        snapshot.route(self.listener.as_str(), &request).cloned()
    }
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = RequestContext;

    /// Takes the snapshot in effect, which the request keeps until it ends, and draws its ID.
    fn new_ctx(&self) -> RequestContext {
        RequestContext {
            snapshot: self.snapshot.load_full(),
            route: None,
            request_id: RequestId::new(),
        }
    }

    /// Applies the keep-alive timeout of the listener and finds the route of the request. The
    /// route decides on compression, which has to be on before the compression module reads the
    /// request headers, right after this.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        // Only replace a keep-alive that is on: it is off when the client asked for that, for
        // HTTP/1.0 without keep-alive, and while the listener drains.
        if session.get_keepalive().is_some() {
            session.set_keepalive(self.keepalive);
        }
        ctx.route = self.find_route(session.req_header(), &ctx.snapshot);
        if ctx.route.as_ref().is_some_and(|route| route.compress) {
            compress::enable(session);
        }
        Ok(())
    }

    /// Answers the requests that do not go to an upstream: 404 without a route, and the
    /// redirects and fixed responses of routes.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        let Some(route) = ctx.route.clone() else {
            session.respond_error(404).await?;
            return Ok(true);
        };
        match &route.handler {
            Handler::Upstream(_) => return Ok(false),
            Handler::Redirect(target) => redirect(session, target, &route.response_headers).await?,
            Handler::Respond(fixed) => respond(session, fixed, &route.response_headers).await?,
        }
        Ok(true)
    }

    /// Picks the target of the request from the upstream of its route.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Box<HttpPeer>> {
        let upstream = ctx
            .route
            .as_ref()
            .and_then(|route| route.upstream())
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "request without upstream"))?;
        let target = upstream
            .select()
            .ok_or_else(|| Error::explain(HTTPStatus(503), "no target available"))?;
        Ok(Box::new(HttpPeer::new(target, false, String::new())))
    }

    /// Tells the upstream about the client, then rewrites the path and changes the headers as
    /// the route asks.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        let client = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip());
        headers::set_forwarded(upstream_request, client, self.tls, &ctx.request_id)?;
        let Some(route) = &ctx.route else {
            return Ok(());
        };
        if let Some(rewrite) = &route.rewrite {
            rewrite_target(upstream_request, rewrite)?;
        }
        route.request_headers.apply(upstream_request)
    }

    /// Asks the client to close the connection when the listener drains, leaves streams and
    /// partial content uncompressed, and changes the headers as the route asks.
    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        if session.is_process_shutting_down() {
            session.set_keepalive(None);
        }
        let Some(route) = &ctx.route else {
            return Ok(());
        };
        if route.compress {
            compress::skip_unsuitable(session, response);
        }
        route.response_headers.apply(response)
    }
}

/// Answers with the redirect of `target`, or with 400 if the target needs a host name and the
/// request has no usable one.
async fn redirect(
    session: &mut Session,
    target: &RedirectTarget,
    response_headers: &HeaderEdits,
) -> pingora::Result<()> {
    let request = session.req_header();
    let location = target
        .location(request_host(request), request_target(request))
        .and_then(|location| HeaderValue::from_bytes(&location).ok());
    let Some(location) = location else {
        return session.respond_error(400).await;
    };
    let mut response = ResponseHeader::build(target.status, Some(3))?;
    response.insert_header("Location", location)?;
    response.insert_header("Content-Length", "0")?;
    response_headers.apply(&mut response)?;
    session
        .write_response_header(Box::new(response), true)
        .await
}

/// Answers with `fixed`. A body goes as plain text unless the header rules set another type,
/// and not at all for a HEAD request.
async fn respond(
    session: &mut Session,
    fixed: &FixedResponse,
    response_headers: &HeaderEdits,
) -> pingora::Result<()> {
    let mut response = ResponseHeader::build(fixed.status, Some(3))?;
    // 204 and 304 have no body, and 204 no length either.
    let bodiless = matches!(fixed.status, 204 | 304);
    if !bodiless {
        response.insert_header("Content-Length", fixed.body.len().to_string())?;
    }
    if !fixed.body.is_empty() {
        response.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    }
    response_headers.apply(&mut response)?;
    let send_body =
        !bodiless && !fixed.body.is_empty() && session.req_header().method != Method::HEAD;
    session
        .write_response_header(Box::new(response), !send_body)
        .await?;
    if send_body {
        session
            .write_response_body(Some(fixed.body.to_vec().into()), true)
            .await?;
    }
    Ok(())
}

/// Rewrites the path of `request` as `rewrite` asks, from its normalized path, and keeps the
/// query as sent.
fn rewrite_target(request: &mut RequestHeader, rewrite: &Rewrite) -> pingora::Result<()> {
    let path = routing::normalize_path(request.uri.path().as_bytes());
    let mut target = routing::encode_path(&routing::rewrite_path(&path, rewrite)).into_bytes();
    let raw = request.raw_path();
    if let Some(query) = raw.iter().position(|&b| b == b'?') {
        target.extend_from_slice(&raw[query..]);
    }
    request.set_raw_path(&target)
}

/// Returns the host name of a request: from the request target in absolute form or the
/// `:authority` of HTTP/2, otherwise from the `Host` header.
fn request_host(request: &RequestHeader) -> Option<&str> {
    let authority = match request.uri.host() {
        Some(host) => host,
        None => request.headers.get("host")?.to_str().ok()?,
    };
    Some(routing::host_name(authority))
}

/// Returns the path and the query of a request as sent.
fn request_target(request: &RequestHeader) -> &[u8] {
    let raw = request.raw_path();
    if raw.starts_with(b"/") {
        return raw;
    }
    // An absolute-form target: its path and query only.
    request
        .uri
        .path_and_query()
        .map_or(b"/", |target| target.as_str().as_bytes())
}

/// The headers of a request, as the router reads them.
struct Headers<'a>(&'a HMap);

impl RequestHeaders for Headers<'_> {
    /// Whether the request has the header.
    fn contains(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    /// Whether one of the values of the header is `value`.
    fn has_value(&self, name: &str, value: &[u8]) -> bool {
        self.0
            .get_all(name)
            .iter()
            .any(|candidate| candidate.as_bytes() == value)
    }
}
