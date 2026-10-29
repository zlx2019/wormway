//! Response compression for routes with `compress = true`, through the compression module that
//! every Pingora proxy has but keeps off.
//!
//! The module picks the first algorithm of the `Accept-Encoding` of the client that it knows,
//! and compresses responses whose type is text-like and that are not encoded already.

use pingora::http::ResponseHeader;
use pingora::modules::http::compression::ResponseCompression;
use pingora::protocols::http::compression::Algorithm;
use pingora::proxy::Session;

/// Levels: the default of zlib for gzip, and levels for Brotli and zstd that compress about as
/// fast.
const LEVELS: [(Algorithm, u32); 3] = [
    (Algorithm::Gzip, 6),
    (Algorithm::Brotli, 4),
    (Algorithm::Zstd, 3),
];

/// Content types whose responses stay as they are: streams of server-sent events, which the
/// compressor would hold back until it has enough data, and gRPC, which compresses on its own.
const STREAMS: [&str; 2] = ["text/event-stream", "application/grpc"];

/// Turns compression on for the response of the request. It has to happen before the module
/// reads the request headers, which it does right after `early_request_filter`.
pub(crate) fn enable(session: &mut Session) {
    if let Some(module) = session
        .downstream_modules_ctx
        .get_mut::<ResponseCompression>()
    {
        for (algorithm, level) in LEVELS {
            module.adjust_algorithm_level(algorithm, level);
        }
    }
}

/// Turns compression off again for a response that must stay as it is: a stream, or a part of
/// the content, whose range counts uncompressed bytes.
pub(crate) fn skip_unsuitable(session: &mut Session, response: &ResponseHeader) {
    let content_type = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    let stream = STREAMS.iter().any(|stream| {
        content_type
            .get(..stream.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(stream.as_bytes()))
    });
    if !stream && response.status != http::StatusCode::PARTIAL_CONTENT {
        return;
    }
    if let Some(module) = session
        .downstream_modules_ctx
        .get_mut::<ResponseCompression>()
        && module.is_header_phase()
    {
        module.adjust_level(0);
    }
}
