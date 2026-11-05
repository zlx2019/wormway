//! Metrics of the requests and of the attempts at the targets of the upstreams. They go to the
//! process-wide recorder, if one is installed.

use std::sync::OnceLock;
use std::time::Duration;

use metrics::{Counter, Histogram, counter, describe_counter, describe_histogram, histogram};
use wormway_core::config::Name;

/// Requests that ended, by listener, route and status.
const REQUESTS_TOTAL: &str = "wormway_http_requests_total";
/// Time from the request header to the end of the response, by route.
const REQUEST_DURATION: &str = "wormway_http_request_duration_seconds";
/// Attempts at the targets of the upstreams, by upstream and result.
const UPSTREAM_REQUESTS_TOTAL: &str = "wormway_upstream_requests_total";
/// Requests turned away by the rate limit of their route, by route.
const RATE_LIMITED_TOTAL: &str = "wormway_rate_limited_total";

/// Registers the help text of every gateway metric.
pub(crate) fn describe() {
    describe_counter!(
        REQUESTS_TOTAL,
        "HTTP requests that ended, by listener, route (empty without one) and status (499 when the client left before the response)."
    );
    describe_histogram!(
        REQUEST_DURATION,
        "Seconds from the request header to the end of the response, by route (empty without one)."
    );
    describe_counter!(
        UPSTREAM_REQUESTS_TOTAL,
        "Attempts at the targets of the upstreams, retries included, by upstream and result: ok, or timeout or error when the target failed."
    );
    describe_counter!(
        RATE_LIMITED_TOTAL,
        "Requests answered with 429 because the rate limit of their route was reached, by route."
    );
}

/// Statuses whose counters [`RequestMetrics`] keeps, in order; the others are looked up in the
/// registry for every request.
const KEPT_STATUSES: [u16; 22] = [
    200, 201, 204, 206, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 408, 413, 429, 499, 500,
    502, 503, 504,
];
/// Results of the attempts at targets.
const RESULTS: [&str; 3] = ["ok", "timeout", "error"];

/// The request metrics of one route, or of the requests that matched no route, on one listener.
/// It keeps the handles it takes from the registry, so that counting a request neither looks
/// them up nor allocates their labels again.
pub(crate) struct RequestMetrics {
    /// The listener.
    listener: Name,
    /// The route, `None` for the requests that matched none.
    route: Option<Name>,
    /// Counters of the requests, by status in [`KEPT_STATUSES`].
    requests: [OnceLock<Counter>; KEPT_STATUSES.len()],
    /// Time to the end of the response.
    duration: OnceLock<Histogram>,
}

impl RequestMetrics {
    /// The metrics of `route` on `listener`; `route` is `None` for the requests that matched no
    /// route.
    pub(crate) fn new(listener: Name, route: Option<Name>) -> Self {
        Self {
            listener,
            route,
            requests: [const { OnceLock::new() }; KEPT_STATUSES.len()],
            duration: OnceLock::new(),
        }
    }

    /// Returns the listener.
    pub(crate) fn listener(&self) -> &Name {
        &self.listener
    }

    /// Counts a request that ended with `status` after `duration`.
    pub(crate) fn record(&self, status: u16, duration: Duration) {
        match KEPT_STATUSES.binary_search(&status) {
            Ok(index) => self.requests[index]
                .get_or_init(|| self.requests(status))
                .increment(1),
            Err(_) => self.requests(status).increment(1),
        }
        self.duration
            .get_or_init(|| histogram!(REQUEST_DURATION, "route" => self.route_label()))
            .record(duration.as_secs_f64());
    }

    /// Looks up the counter of the requests that ended with `status`.
    fn requests(&self, status: u16) -> Counter {
        counter!(
            REQUESTS_TOTAL,
            "listener" => self.listener.to_string(),
            "route" => self.route_label(),
            "status" => status.to_string()
        )
    }

    /// Returns the label of the route: empty for the requests that matched none.
    fn route_label(&self) -> String {
        self.route.as_ref().map(Name::to_string).unwrap_or_default()
    }
}

/// The metrics of the attempts at the targets of one upstream, which keep their handles as
/// [`RequestMetrics`] does.
pub(crate) struct AttemptMetrics {
    /// The upstream.
    upstream: Name,
    /// Counters of the attempts, by result in [`RESULTS`].
    attempts: [OnceLock<Counter>; RESULTS.len()],
}

impl AttemptMetrics {
    /// The metrics of the attempts at the targets of `upstream`.
    pub(crate) fn new(upstream: Name) -> Self {
        Self {
            upstream,
            attempts: [const { OnceLock::new() }; RESULTS.len()],
        }
    }

    /// Counts an attempt that ended with `result`: `ok`, `timeout` or `error`.
    pub(crate) fn record(&self, result: &'static str) {
        let attempts = || counter!(UPSTREAM_REQUESTS_TOTAL, "upstream" => self.upstream.to_string(), "result" => result);
        match RESULTS.iter().position(|known| *known == result) {
            Some(index) => self.attempts[index].get_or_init(attempts).increment(1),
            None => attempts().increment(1),
        }
    }
}

/// Counts a request of `route` that its rate limit turned away.
pub(crate) fn rate_limited(route: &Name) {
    counter!(RATE_LIMITED_TOTAL, "route" => route.to_string()).increment(1);
}
