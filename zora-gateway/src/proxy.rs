//! The Pingora application of an HTTP listener: finds the route of each request and picks its
//! target.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType, HTTPStatus};
use zora_core::config::Name;
use zora_core::routing;

use crate::snapshot::{CompiledRoute, GatewaySnapshot};

/// Serves the requests of one listener.
pub(crate) struct Proxy {
    /// The listener.
    listener: Name,
    /// Routes and upstreams in effect.
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    /// Seconds a kept-alive HTTP/1.1 connection waits for its next request; `None` turns
    /// keep-alive off.
    keepalive: Option<u64>,
}

/// State of one request.
pub(crate) struct RequestContext {
    /// Routes and upstreams when the request started, kept until it ends.
    snapshot: Arc<GatewaySnapshot>,
    /// Route of the request, once found.
    route: Option<Arc<CompiledRoute>>,
}

impl Proxy {
    /// Creates the application of `listener`.
    pub(crate) fn new(
        listener: Name,
        snapshot: Arc<ArcSwap<GatewaySnapshot>>,
        keepalive: Option<u64>,
    ) -> Self {
        Self {
            listener,
            snapshot,
            keepalive,
        }
    }
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = RequestContext;

    /// Takes the snapshot in effect; the request keeps it until it ends.
    fn new_ctx(&self) -> RequestContext {
        RequestContext {
            snapshot: self.snapshot.load_full(),
            route: None,
        }
    }

    /// Applies the keep-alive timeout of the listener.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        // Only replace a keep-alive that is on: it is off when the client asked for that, for
        // HTTP/1.0 without keep-alive, and while the listener drains.
        if session.get_keepalive().is_some() {
            session.set_keepalive(self.keepalive);
        }
        Ok(())
    }

    /// Finds the route of the request, and answers 404 when there is none.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        let request = session.req_header();
        ctx.route = ctx
            .snapshot
            .route(
                self.listener.as_str(),
                request_host(request),
                request.uri.path(),
            )
            .cloned();
        if ctx.route.is_some() {
            return Ok(false);
        }
        session.respond_error(404).await?;
        Ok(true)
    }

    /// Picks the target of the request from the upstream of its route.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<Box<HttpPeer>> {
        let route = ctx
            .route
            .as_ref()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "request without a route"))?;
        let target = route
            .upstream
            .select()
            .ok_or_else(|| Error::explain(HTTPStatus(503), "no target available"))?;
        Ok(Box::new(HttpPeer::new(target, false, String::new())))
    }

    /// Asks the client to close the connection when the listener drains, so that it does not
    /// send another request on it.
    async fn response_filter(
        &self,
        session: &mut Session,
        _response: &mut ResponseHeader,
        _ctx: &mut RequestContext,
    ) -> pingora::Result<()> {
        if session.is_process_shutting_down() {
            session.set_keepalive(None);
        }
        Ok(())
    }
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
