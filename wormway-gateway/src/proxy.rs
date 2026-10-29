//! The Pingora application of an HTTP listener: finds the route of each request, then forwards
//! the request to the upstream of the route or answers it, with the changes the route asks for.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderValue, Version};
use pingora::http::{HMap, Method, RequestHeader, ResponseHeader};
use pingora::lb::Backend;
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorSource, ErrorType, HTTPStatus};
use wormway_core::config::{HashKey, Name, Rewrite};
use wormway_core::routing::{self, Request, RequestHeaders};

use crate::compress;
use crate::headers::{self, HeaderEdits, RequestId};
use crate::route::{CompiledRoute, FixedResponse, Handler, RedirectTarget};
use crate::snapshot::GatewaySnapshot;
use crate::upstream::{CompiledUpstream, Inflight};

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
    /// Targets the request went to, the current one last.
    tried: Vec<Backend>,
    /// Target of the next attempt, picked when an attempt failed.
    next: Option<Backend>,
    /// Attempts made at other targets after a connection failed.
    retries: u32,
    /// The request counted at its target, for upstreams balanced by requests in progress.
    inflight: Option<Inflight>,
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
            tried: Vec::new(),
            next: None,
            retries: 0,
            inflight: None,
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

    /// Picks the target of the request from the upstream of its route, unless a failed attempt
    /// picked the next one already.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Box<HttpPeer>> {
        let route = ctx
            .route
            .clone()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "request without route"))?;
        let upstream = route
            .upstream()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "request without upstream"))?;
        let target = match ctx.next.take() {
            Some(target) => target,
            None => upstream
                .runtime
                .select(&selection_key(session, upstream), |_| true)
                .ok_or_else(|| Error::explain(HTTPStatus(503), "no target available"))?,
        };
        ctx.inflight = upstream.runtime.track(&target);
        let peer = upstream.peer(&target, &route.timeouts);
        ctx.tried.push(target);
        Ok(Box::new(peer))
    }

    /// Tries another target when connecting failed, as many times as the upstream allows and
    /// as long as there is a target the request has not tried. Nothing was sent, so this is
    /// safe for every method.
    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut RequestContext,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let Some(route) = ctx.route.clone() else {
            return e;
        };
        let Some(upstream) = route.upstream() else {
            return e;
        };
        if ctx.retries >= upstream.retries() {
            return e;
        }
        let tried = &ctx.tried;
        let next = upstream
            .runtime
            .select(&selection_key(session, upstream), |target| {
                !tried.iter().any(|seen| seen.addr == target.addr)
            });
        if let Some(next) = next {
            ctx.retries += 1;
            ctx.next = Some(next);
            e.set_retry(true);
        }
        e
    }

    /// Retries over a new connection to the same target only when a reused connection turned
    /// out closed, as Pingora does: for idempotent requests whose body can be sent again, and
    /// never once the response has started.
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut RequestContext,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        if session.response_written().is_some()
            || !session.req_header().method.is_idempotent()
            || session.as_ref().retry_buffer_truncated()
        {
            e.set_retry(false);
        } else {
            e.retry.decide_reuse(client_reused);
        }
        if e.retry() {
            ctx.next = ctx.tried.last().cloned();
        }
        e
    }

    /// Answers a request that could not be proxied: 504 when the upstream ran out of time, 502
    /// for its other failures, as Nginx does.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut RequestContext,
    ) -> FailToProxy {
        let code = error_status(e);
        if code > 0
            && let Err(error) = session.respond_error(code).await
        {
            tracing::debug!("cannot send the error response: {error}");
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
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
        // An HTTP/1.0 upstream does not turn the response into HTTP/1.0, which would make HTTP/1.1
        // clients give up keep-alive; Pingora frames the body for HTTP/1.1 already.
        if response.version < Version::HTTP_11 {
            response.set_version(Version::HTTP_11);
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

/// Returns the status of the answer to a request that failed with `e`, or 0 when the client is
/// gone: Pingora's choice, except 504 for upstream timeouts.
fn error_status(e: &Error) -> u16 {
    match (e.etype(), e.esource()) {
        (HTTPStatus(code), _) => *code,
        (
            ErrorType::ConnectTimedout | ErrorType::ReadTimedout | ErrorType::WriteTimedout,
            ErrorSource::Upstream,
        ) => 504,
        (_, ErrorSource::Upstream) => 502,
        (
            ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed,
            ErrorSource::Downstream,
        ) => 0,
        (_, ErrorSource::Downstream) => 400,
        (_, ErrorSource::Internal | ErrorSource::Unset) => 500,
    }
}

/// Returns what consistent hashing hashes for a request to `upstream`: its key, or the client
/// IP address when the request does not have the key. Empty for other ways of balancing.
fn selection_key(session: &Session, upstream: &CompiledUpstream) -> Vec<u8> {
    let Some(key) = upstream.hash_key() else {
        return Vec::new();
    };
    let request = session.req_header();
    let found = match key {
        HashKey::ClientIp => None,
        HashKey::Uri => Some(request_target(request)),
        HashKey::Header(name) => request
            .headers
            .get(name.as_str())
            .map(|value| value.as_bytes()),
        HashKey::Cookie(name) => cookie(&request.headers, name),
    };
    match found {
        Some(key) => key.to_vec(),
        None => client_ip(session).map_or_else(Vec::new, |ip| match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        }),
    }
}

/// Returns the IP address of the client, IPv4 addresses mapped to IPv6 as IPv4.
fn client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip().to_canonical())
}

/// Returns the value of cookie `name` in `headers`, as sent.
fn cookie<'a>(headers: &'a HMap, name: &str) -> Option<&'a [u8]> {
    headers
        .get_all("cookie")
        .iter()
        .flat_map(|value| value.as_bytes().split(|&b| b == b';'))
        .find_map(|pair| {
            let pair = pair.trim_ascii();
            let (key, value) = pair.split_at(pair.iter().position(|&b| b == b'=')?);
            (key == name.as_bytes()).then_some(&value[1..])
        })
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
