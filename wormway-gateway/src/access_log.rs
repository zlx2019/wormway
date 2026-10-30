//! The access log: one line per request, as JSON or in the combined log format, written by a
//! thread of its own so that requests never wait for the output.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, SystemTime};

use wormway_core::config::{AccessLogFormat, AccessLogSettings, Name};
use wormway_core::time;

/// Lines that may wait for the writer; more are dropped and counted.
const QUEUE: usize = 8192;
/// How often an idle writer looks whether it should open the file again.
const IDLE: Duration = Duration::from_secs(1);
/// Lines the writer could not keep up with.
const DROPPED_TOTAL: &str = "wormway_access_log_dropped_total";

/// The access log. Cloning it gives another handle to the same writer, which stops once every
/// handle is dropped.
#[derive(Clone)]
pub struct AccessLog {
    /// Requests waiting for the writer.
    queue: SyncSender<Record>,
    /// Asks the writer to open the file again.
    reopen: Arc<AtomicBool>,
}

impl AccessLog {
    /// Opens the access log of `settings`, whose path is relative to `base`, the directory of
    /// the configuration file, and starts its writer.
    pub fn open(settings: &AccessLogSettings, base: &Path) -> io::Result<Self> {
        let output = Output::open(settings.path.as_ref().map(|path| base.join(path)))?;
        metrics::describe_counter!(
            DROPPED_TOTAL,
            "Access log lines dropped because the writer could not keep up."
        );
        let (queue, waiting) = mpsc::sync_channel(QUEUE);
        let reopen = Arc::new(AtomicBool::new(false));
        let writer = Writer {
            output,
            format: settings.format,
            reopen: reopen.clone(),
            failing: false,
        };
        std::thread::Builder::new()
            .name("wormway-access-log".to_owned())
            .spawn(move || writer.run(waiting))?;
        Ok(Self { queue, reopen })
    }

    /// Opens the file again, for example after logrotate moved it, within a second. Lines go to
    /// standard output as before.
    pub fn reopen(&self) {
        self.reopen.store(true, Ordering::Relaxed);
    }

    /// Hands `record` to the writer, or drops and counts it when the writer is behind.
    pub(crate) fn write(&self, record: Record) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.queue.try_send(record)
        {
            metrics::counter!(DROPPED_TOTAL).increment(1);
        }
    }
}

/// What the access log keeps of a request.
pub(crate) struct Record {
    /// When the request ended.
    pub(crate) time: SystemTime,
    /// Address of the client.
    pub(crate) client: Option<SocketAddr>,
    /// The method.
    pub(crate) method: String,
    /// The host, from the `Host` header or the request target.
    pub(crate) host: Option<String>,
    /// The path and the query, as sent.
    pub(crate) uri: String,
    /// The HTTP version, such as `HTTP/1.1`.
    pub(crate) protocol: &'static str,
    /// The status of the response, 499 when the client left before any.
    pub(crate) status: u16,
    /// Bytes of the request body.
    pub(crate) request_bytes: usize,
    /// Bytes of the response body.
    pub(crate) response_bytes: usize,
    /// From the request header to the end of the response.
    pub(crate) duration: Duration,
    /// The listener.
    pub(crate) listener: Name,
    /// The route, if one matched.
    pub(crate) route: Option<Name>,
    /// The upstream of the route, if it has one.
    pub(crate) upstream: Option<Name>,
    /// The last target the request went to.
    pub(crate) target: Option<SocketAddr>,
    /// From choosing the first target to the response header of the last one.
    pub(crate) upstream_duration: Option<Duration>,
    /// The request ID, as sent to the upstream in `X-Request-Id`.
    pub(crate) request_id: String,
    /// The `User-Agent` header.
    pub(crate) user_agent: Option<String>,
    /// The `Referer` header.
    pub(crate) referer: Option<String>,
    /// The TLS version, such as `TLSv1.3`, for requests over TLS.
    pub(crate) tls: Option<String>,
    /// Why the request failed, if it did.
    pub(crate) error: Option<String>,
}

impl Record {
    /// Writes the record as one line of JSON, without the line break.
    pub(crate) fn json(&self, line: &mut String) {
        let mut object = JsonObject::new(line);
        object.string("time", Some(&time::rfc3339(self.time)));
        object.string(
            "client_ip",
            self.client.map(|client| client.ip().to_string()).as_deref(),
        );
        object.number("client_port", self.client.map(|client| client.port()));
        object.string("method", Some(&self.method));
        object.string("host", self.host.as_deref());
        object.string("uri", Some(&self.uri));
        object.string("protocol", Some(self.protocol));
        object.number("status", Some(self.status));
        object.number("request_bytes", Some(self.request_bytes));
        object.number("response_bytes", Some(self.response_bytes));
        object.seconds("duration", Some(self.duration));
        object.string("listener", Some(self.listener.as_str()));
        object.string("route", self.route.as_ref().map(Name::as_str));
        object.string("upstream", self.upstream.as_ref().map(Name::as_str));
        object.string(
            "target",
            self.target.map(|target| target.to_string()).as_deref(),
        );
        object.seconds("upstream_duration", self.upstream_duration);
        object.string("request_id", Some(&self.request_id));
        object.string("user_agent", self.user_agent.as_deref());
        object.string("referer", self.referer.as_deref());
        object.string("tls", self.tls.as_deref());
        object.string("error", self.error.as_deref());
        object.close();
    }

    /// Writes the record in the combined log format of Nginx, without the line break:
    /// `client - - [time] "request" status bytes "referer" "user agent"`.
    pub(crate) fn combined(&self, line: &mut String) {
        let client = self.client.map(|client| client.ip().to_string());
        line.push_str(client.as_deref().unwrap_or("-"));
        let _ = write!(line, " - - [{}] \"", time::common_log(self.time));
        push_escaped(line, &self.method);
        line.push(' ');
        push_escaped(line, &self.uri);
        let _ = write!(
            line,
            " {}\" {} {} \"",
            self.protocol, self.status, self.response_bytes
        );
        push_escaped(line, self.referer.as_deref().unwrap_or("-"));
        line.push_str("\" \"");
        push_escaped(line, self.user_agent.as_deref().unwrap_or("-"));
        line.push('"');
    }
}

/// Writes the fields of a JSON object.
struct JsonObject<'a> {
    /// The line.
    line: &'a mut String,
    /// Whether a field was written, so that the next one needs a comma.
    started: bool,
}

impl<'a> JsonObject<'a> {
    /// Opens the object at the end of `line`.
    fn new(line: &'a mut String) -> Self {
        line.push('{');
        Self {
            line,
            started: false,
        }
    }

    /// Writes the name of the next field.
    fn name(&mut self, name: &str) {
        if self.started {
            self.line.push(',');
        }
        self.started = true;
        let _ = write!(self.line, "\"{name}\":");
    }

    /// Writes a string field, or null.
    fn string(&mut self, name: &str, value: Option<&str>) {
        self.name(name);
        match value {
            Some(value) => push_json_string(self.line, value),
            None => self.line.push_str("null"),
        }
    }

    /// Writes a number field, or null.
    fn number(&mut self, name: &str, value: Option<impl std::fmt::Display>) {
        self.name(name);
        match value {
            Some(value) => {
                let _ = write!(self.line, "{value}");
            }
            None => self.line.push_str("null"),
        }
    }

    /// Writes a duration in seconds to the microsecond, or null.
    fn seconds(&mut self, name: &str, value: Option<Duration>) {
        self.name(name);
        match value {
            Some(value) => {
                let _ = write!(self.line, "{:.6}", value.as_secs_f64());
            }
            None => self.line.push_str("null"),
        }
    }

    /// Closes the object.
    fn close(self) {
        self.line.push('}');
    }
}

/// Writes `value` as a JSON string.
fn push_json_string(line: &mut String, value: &str) {
    line.push('"');
    for character in value.chars() {
        match character {
            '"' => line.push_str("\\\""),
            '\\' => line.push_str("\\\\"),
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            control if control < ' ' || control == '\u{7f}' => {
                let _ = write!(line, "\\u{:04x}", u32::from(control));
            }
            other => line.push(other),
        }
    }
    line.push('"');
}

/// Writes `value` as Nginx does in the quoted fields of its logs: `"`, `\`, control characters
/// and bytes beyond ASCII as `\xHH`.
fn push_escaped(line: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte == b'"' || byte == b'\\' || !(0x20..0x7f).contains(&byte) {
            let _ = write!(line, "\\x{byte:02X}");
        } else {
            line.push(char::from(byte));
        }
    }
}

/// Writes the lines of the requests in the background.
struct Writer {
    /// Where the lines go.
    output: Output,
    /// Format of the lines.
    format: AccessLogFormat,
    /// Set when the file should be opened again.
    reopen: Arc<AtomicBool>,
    /// Whether writing failed last time, so that a failure is logged once.
    failing: bool,
}

impl Writer {
    /// Writes the records of `waiting` until every handle of the log is dropped, flushing
    /// whenever no more are waiting.
    fn run(mut self, waiting: Receiver<Record>) {
        let mut line = String::new();
        loop {
            match waiting.recv_timeout(IDLE) {
                Ok(record) => {
                    self.write(&record, &mut line);
                    while let Ok(record) = waiting.try_recv() {
                        self.write(&record, &mut line);
                    }
                    let flushed = self.output.flush();
                    self.outcome(flushed);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if self.reopen.swap(false, Ordering::Relaxed) {
                self.output.reopen();
            }
        }
    }

    /// Writes the line of `record`, using `line` as a buffer.
    fn write(&mut self, record: &Record, line: &mut String) {
        line.clear();
        match self.format {
            AccessLogFormat::Json => record.json(line),
            AccessLogFormat::Combined => record.combined(line),
        }
        line.push('\n');
        let written = self.output.write(line.as_bytes());
        self.outcome(written);
    }

    /// Logs the first failure to write and the recovery after it.
    fn outcome(&mut self, result: io::Result<()>) {
        match (result, self.failing) {
            (Err(error), false) => {
                tracing::error!(
                    "cannot write the access log: {error}; lines are lost until it works again"
                );
                self.failing = true;
            }
            (Ok(()), true) => {
                tracing::info!("the access log is written again");
                self.failing = false;
            }
            _ => {}
        }
    }
}

/// Where the lines of the access log go.
enum Output {
    /// Standard output.
    Stdout(BufWriter<io::Stdout>),
    /// A file, which can be opened again.
    File {
        /// Path of the file.
        path: PathBuf,
        /// The file.
        file: BufWriter<File>,
    },
}

impl Output {
    /// Opens the file at `path`, creating it and its directory if needed, or standard output
    /// without a path.
    fn open(path: Option<PathBuf>) -> io::Result<Self> {
        match path {
            Some(path) => {
                let file = open_file(&path).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("cannot open the access log {}: {error}", path.display()),
                    )
                })?;
                Ok(Self::File {
                    path,
                    file: BufWriter::new(file),
                })
            }
            None => Ok(Self::Stdout(BufWriter::new(io::stdout()))),
        }
    }

    /// Writes `bytes`.
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.write_all(bytes),
            Self::File { file, .. } => file.write_all(bytes),
        }
    }

    /// Writes what is buffered.
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.flush(),
            Self::File { file, .. } => file.flush(),
        }
    }

    /// Opens the file again; on failure the lines keep going to the file open before.
    fn reopen(&mut self) {
        let Self::File { path, file } = self else {
            return;
        };
        if let Err(error) = file.flush() {
            tracing::warn!(path = %path.display(), "cannot write the access log: {error}");
        }
        match open_file(path) {
            Ok(opened) => *file = BufWriter::new(opened),
            Err(error) => tracing::error!(
                path = %path.display(),
                "cannot open the access log again: {error}; lines keep going to the file open before"
            ),
        }
    }
}

/// Opens `path` for appending, creating the file and its directory if needed.
fn open_file(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    /// A request with every field set, and a quote, a backslash, a tab and a non-ASCII
    /// character in the headers.
    fn record() -> Record {
        Record {
            time: UNIX_EPOCH + Duration::from_millis(1_761_696_000_123),
            client: Some("[::1]:52000".parse().unwrap()),
            method: "GET".to_owned(),
            host: Some("api.local".to_owned()),
            uri: "/v1/users?q=a b".to_owned(),
            protocol: "HTTP/1.1",
            status: 200,
            request_bytes: 0,
            response_bytes: 1234,
            duration: Duration::from_micros(1_500),
            listener: "web".parse().unwrap(),
            route: Some("api".parse().unwrap()),
            upstream: Some("app".parse().unwrap()),
            target: Some("10.0.0.1:80".parse().unwrap()),
            upstream_duration: Some(Duration::from_micros(1_200)),
            request_id: "0123abcd".to_owned(),
            user_agent: Some("say \"hi\"\t\\ é".to_owned()),
            referer: None,
            tls: Some("TLSv1.3".to_owned()),
            error: None,
        }
    }

    /// JSON lines hold every field, nulls for those not set, and escaped strings.
    #[test]
    fn writes_json_lines() {
        let mut line = String::new();
        record().json(&mut line);
        assert_eq!(
            line,
            r#"{"time":"2025-10-29T00:00:00.123Z","client_ip":"::1","client_port":52000,"method":"GET","host":"api.local","uri":"/v1/users?q=a b","protocol":"HTTP/1.1","status":200,"request_bytes":0,"response_bytes":1234,"duration":0.001500,"listener":"web","route":"api","upstream":"app","target":"10.0.0.1:80","upstream_duration":0.001200,"request_id":"0123abcd","user_agent":"say \"hi\"\t\\ é","referer":null,"tls":"TLSv1.3","error":null}"#
        );
    }

    /// Combined lines look like those of Nginx, escaped the same way.
    #[test]
    fn writes_combined_lines() {
        let mut line = String::new();
        record().combined(&mut line);
        assert_eq!(
            line,
            r#"::1 - - [29/Oct/2025:00:00:00 +0000] "GET /v1/users?q=a b HTTP/1.1" 200 1234 "-" "say \x22hi\x22\x09\x5C \xC3\xA9""#
        );
    }

    /// Lines reach the file; after the file is moved away and the log reopened, new lines go to
    /// a new file at the same path.
    #[test]
    fn reopens_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let settings = AccessLogSettings {
            format: AccessLogFormat::Combined,
            path: Some(PathBuf::from("logs/access.log")),
        };
        let log = AccessLog::open(&settings, dir.path()).unwrap();
        let path = dir.path().join("logs/access.log");
        let moved = dir.path().join("logs/access.log.1");
        log.write(record());
        wait_for_lines(&path, 1);
        std::fs::rename(&path, &moved).unwrap();
        log.reopen();
        std::thread::sleep(IDLE + Duration::from_millis(200));
        log.write(record());
        wait_for_lines(&path, 1);
        assert_eq!(line_count(&moved), 1);
    }

    /// Returns the number of lines in the file at `path`, 0 if it does not exist.
    fn line_count(path: &Path) -> usize {
        std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
    }

    /// Waits up to 10 seconds for the file at `path` to have `count` lines.
    fn wait_for_lines(path: &Path, count: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while line_count(path) < count {
            assert!(
                std::time::Instant::now() < deadline,
                "no line in {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
