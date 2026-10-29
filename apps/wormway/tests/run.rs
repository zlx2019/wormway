//! End-to-end tests of `wormway run`: startup, the gateway, the Admin API, reload on SIGHUP and
//! shutdown on SIGINT or SIGTERM; and of the `wormway config` commands against a running Wormway.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// How long to wait for a log line or for the process to exit.
const PATIENCE: Duration = Duration::from_secs(10);

/// The Admin API on any free port, so that tests can run side by side.
const ADMIN: &str = "[admin]\nlisten = \"127.0.0.1:0\"\n";

/// File mode without listeners: starts with every binary build.
const EMPTY: &str = "version = 1\n[config]\nsource = \"file\"\n[admin]\nlisten = \"127.0.0.1:0\"\n";

/// Writes `text` as `wormway.toml` into a fresh directory named `name` in Cargo's temporary
/// directory for tests, and returns the path of the file. The data directory goes next to it.
fn temp_config(name: &str, text: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the test directory");
    let path = dir.join("wormway.toml");
    std::fs::write(&path, text).expect("write the test configuration");
    path
}

/// Starts an HTTP server on a free loopback port that answers every request with `body`, and
/// returns its address.
fn upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let addr = listener.local_addr().expect("upstream address");
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            // Skip the request head, then answer and close.
            let mut request = BufReader::new(stream.try_clone().expect("clone the stream"));
            let mut line = String::new();
            while request.read_line(&mut line).is_ok_and(|read| read > 2) {
                line.clear();
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    addr
}

/// Writes a self-signed certificate for `wormway.test` and its key into `dir` as `<file>.crt` and
/// `<file>.key`.
fn write_certificate(dir: &Path, file: &str) {
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = rcgen::CertificateParams::new(vec!["wormway.test".to_owned()])
        .expect("certificate parameters")
        .self_signed(&key)
        .expect("certificate");
    std::fs::write(dir.join(format!("{file}.crt")), cert.pem()).expect("write the certificate");
    std::fs::write(dir.join(format!("{file}.key")), key.serialize_pem()).expect("write the key");
}

/// Sends `GET path` with an optional token to the Admin API at `addr`, and returns the status
/// code and the body.
fn get(addr: &str, path: &str, token: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to the Admin API");
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: wormway\r\n{authorization}Connection: close\r\n\r\n"
    )
    .expect("send the request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read the response");
    let status = response
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// Runs `wormway config ARGS -c path` with the Admin API token `token`, and returns the exit
/// code, standard output and standard error.
fn wormway_config(path: &Path, token: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wormway"))
        .arg("config")
        .args(args)
        .arg("-c")
        .arg(path)
        .env_remove("WORMWAY_CONFIG")
        .env("WORMWAY_ADMIN_TOKEN", token)
        .output()
        .expect("run wormway config");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Starts `wormway run` in database mode with the Admin API token `token`, and returns it with
/// the address of the Admin API. The `wormway config` commands find the API through the file, so
/// the port the API got is written into it.
fn start_for_config(name: &str, token: &str) -> (Wormway, PathBuf, String) {
    let path = temp_config(name, &format!("version = 1\n{ADMIN}"));
    let mut wormway = Wormway::start_with_env(&path, &[("WORMWAY_ADMIN_TOKEN", token)]);
    let addr = wormway.admin_addr();
    wormway.wait_for("Wormway is ready");
    let text = format!("version = 1\n[admin]\nlisten = \"{addr}\"\n");
    std::fs::write(&path, text).expect("write the Admin API address");
    (wormway, path, addr)
}

/// A `wormway run` process and its log lines.
struct Wormway {
    /// The process.
    child: Child,
    /// Lines of standard error, read by a background thread.
    lines: Receiver<String>,
    /// Lines received so far, shown when a wait fails.
    seen: Vec<String>,
}

impl Wormway {
    /// Starts `wormway run` with the configuration file at `path`.
    fn start(path: &Path) -> Self {
        Self::start_with_env(path, &[])
    }

    /// Starts `wormway run` with the configuration file at `path` and extra environment variables.
    fn start_with_env(path: &Path, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wormway"))
            .args(["run", "-c"])
            .arg(path)
            .env_remove("WORMWAY_CONFIG")
            .env_remove("WORMWAY_ADMIN_TOKEN")
            .envs(env.iter().copied())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start wormway");
        let stderr = child.stderr.take().expect("piped stderr");
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Waits for a log line that contains `text` and returns it.
    fn wait_for(&mut self, text: &str) -> String {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.contains(text) => return line,
                Ok(line) => self.seen.push(line),
                Err(_) => panic!(
                    "no log line contains {text:?}, got:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Waits until listener `name` listens and returns its first address.
    fn listener_addr(&mut self, name: &str) -> String {
        let line = self.wait_for(&format!("listening listener={name}"));
        line.split_once("addr=")
            .map(|(_, addr)| addr.trim().to_owned())
            .expect("address in the log line")
    }

    /// Waits until the Admin API listens and returns its address.
    fn admin_addr(&mut self) -> String {
        let line = self.wait_for("Admin API listening");
        line.split_once("addr=")
            .map(|(_, addr)| addr.trim().to_owned())
            .expect("address in the log line")
    }

    /// Sends the signal `name`, such as `HUP` or `TERM`.
    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args(["-s", name, &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -s {name} failed");
    }

    /// Waits for the process to exit and returns its exit code.
    fn exit_code(&mut self) -> Option<i32> {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("check the process") {
                return status.code();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("Wormway did not exit, log:\n{}", self.seen.join("\n"));
    }
}

impl Drop for Wormway {
    /// Kills the process if a test failed while it was running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `wormway run` starts and stops cleanly on SIGTERM.
#[test]
fn stops_on_sigterm() {
    let mut wormway = Wormway::start(&temp_config("run-sigterm", EMPTY));
    wormway.wait_for("Wormway is ready");
    wormway.signal("TERM");
    wormway.wait_for("stopped");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// SIGHUP rereads the file. An invalid file is reported and the running configuration stays;
/// changed static settings are only reported.
#[test]
fn reloads_on_sighup() {
    let path = temp_config("run-sighup", EMPTY);
    let mut wormway = Wormway::start(&path);
    wormway.wait_for("Wormway is ready");

    std::fs::write(&path, format!("{EMPTY}[server]\nthread = 4\n")).expect("write");
    wormway.signal("HUP");
    let failed = wormway.wait_for("reload failed");
    assert!(failed.contains("unknown field `thread`"), "{failed}");

    std::fs::write(&path, format!("{EMPTY}[server]\nthreads = 4\n")).expect("write");
    wormway.signal("HUP");
    wormway.wait_for("static settings changed");
    let reloaded = wormway.wait_for("configuration reloaded");
    assert!(reloaded.contains("config_version=2"), "{reloaded}");

    wormway.signal("INT");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// The gateway forwards the requests of an HTTP listener to the upstream of their route.
#[test]
fn proxies_http_requests() {
    let target = upstream("hello from the upstream");
    let config = format!(
        "{EMPTY}[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{target}\"]\n"
    );
    let mut wormway = Wormway::start(&temp_config("run-proxy", &config));
    let addr = wormway.listener_addr("web");
    wormway.wait_for("Wormway is ready");

    assert_eq!(
        get(&addr, "/", None),
        (200, "hello from the upstream".to_owned())
    );
    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// SIGHUP with dynamic settings from the database applies them again, which reads the
/// certificate files again. Relative paths are relative to the configuration file.
#[test]
fn reloads_certificate_files_on_sighup() {
    let (mut wormway, path, _) = start_for_config("run-certificates", "cli-token");
    let dir = path.parent().expect("directory");
    write_certificate(dir, "site");
    let file = path.with_file_name("dynamic.toml");
    let certificate = "[certificates.site]\ncert = \"site.crt\"\nkey = \"site.key\"\n";
    std::fs::write(&file, format!("version = 1\n{certificate}")).expect("write");
    let file_arg = file.to_str().expect("UTF-8 path");
    let (code, _, err) = wormway_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(0), "{err}");
    wormway.wait_for("certificate loaded certificate=site");

    write_certificate(dir, "site");
    wormway.signal("HUP");
    wormway.wait_for("reloading the certificate files");
    wormway.wait_for("certificate loaded certificate=site");
    wormway.wait_for("configuration reloaded");
    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// When Pingora cannot load the system root certificates, the listener fails with the reason
/// instead of crashing the process.
#[test]
fn reports_unreadable_root_certificates() {
    let target = upstream("unused");
    let config = format!(
        "{EMPTY}[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{target}\"]\n"
    );
    let path = temp_config("run-root-certificates", &config);
    let missing = path.with_file_name("missing-ca.pem");
    let mut wormway = Wormway::start_with_env(
        &path,
        &[("SSL_CERT_FILE", missing.to_str().expect("UTF-8"))],
    );
    wormway.wait_for("Error: listener web: cannot create the service");
    let cause = wormway.wait_for("cannot load the system root certificates");
    assert!(cause.contains("could not load certs from file"), "{cause}");
    assert_eq!(wormway.exit_code(), Some(1));
}

/// An invalid file is reported like `wormway check` does, before anything starts.
#[test]
fn reports_invalid_files() {
    let path = temp_config("run-invalid", "version = 1\n[log]\nlevel = \"info,=x=\"\n");
    let mut wormway = Wormway::start(&path);
    let line = wormway.wait_for("error: log.level: invalid filter directive");
    assert!(line.starts_with(&path.display().to_string()), "{line}");
    assert_eq!(wormway.exit_code(), Some(1));
}

/// The Admin API answers health checks without a token and everything else with it. The token
/// file is created on first start, readable by its owner only.
#[test]
fn serves_the_admin_api() {
    let path = temp_config("run-admin", &format!("version = 1\n{ADMIN}"));
    let mut wormway = Wormway::start(&path);
    let addr = wormway.admin_addr();
    wormway.wait_for("Wormway is ready");

    assert_eq!(get(&addr, "/healthz", None).0, 200);
    assert_eq!(get(&addr, "/api/v1/status", None).0, 401);
    let token_file = path.with_file_name("data").join("admin.token");
    let token = std::fs::read_to_string(&token_file).expect("token file");
    let (status, body) = get(&addr, "/api/v1/status", Some(token.trim()));
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(r#""source":"db""#), "{body}");
    let (status, body) = get(&addr, "/metrics", Some(token.trim()));
    assert_eq!(status, 200);
    assert!(body.contains("wormway_build_info"), "{body}");

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&token_file)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// `WORMWAY_ADMIN_TOKEN` replaces the token file.
#[test]
fn takes_the_token_from_the_environment() {
    let path = temp_config("run-admin-env", &format!("version = 1\n{ADMIN}"));
    let mut wormway = Wormway::start_with_env(&path, &[("WORMWAY_ADMIN_TOKEN", "from-env")]);
    let addr = wormway.admin_addr();
    assert_eq!(get(&addr, "/api/v1/status", Some("from-env")).0, 200);
    assert!(!path.with_file_name("data").join("admin.token").exists());
    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// The Admin API reports the health of the targets that the gateway checks.
#[test]
fn reports_the_health_of_upstreams() {
    let target = upstream("hello from the upstream");
    let closed = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port");
    let config = format!(
        "{EMPTY}[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{target}\", \"{closed}\"]\nhealth_check = {{ kind = \"tcp\", interval = \"1h\" }}\n"
    );
    let path = temp_config("run-health", &config);
    let mut wormway = Wormway::start_with_env(&path, &[("WORMWAY_ADMIN_TOKEN", "health-token")]);
    let addr = wormway.admin_addr();
    wormway.wait_for("Wormway is ready");

    let (status, body) = get(&addr, "/api/v1/status/upstreams", Some("health-token"));
    assert_eq!(status, 200, "{body}");
    let report: serde_json::Value = serde_json::from_str(&body).expect("a JSON answer");
    let state = |address: SocketAddr| {
        let targets = report["upstreams"][0]["targets"].as_array();
        let target = targets
            .into_iter()
            .flatten()
            .find(|target| target["address"] == address.to_string())?;
        Some(format!("{} {}", target["state"], target["reason"]))
    };
    assert_eq!(
        state(target).as_deref(),
        Some(r#""healthy" null"#),
        "{body}"
    );
    assert_eq!(
        state(closed).as_deref(),
        Some(r#""unhealthy" "connection refused""#),
        "{body}"
    );
    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// `wormway config apply` saves the settings of a file as a version from the command line, and
/// `wormway config export` writes them in a form that `apply` reads back.
#[test]
fn applies_and_exports_dynamic_settings() {
    let (mut wormway, path, addr) = start_for_config("config-apply", "cli-token");
    let (code, empty, _) = wormway_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(0));
    assert!(empty.starts_with("version = 1\n"), "{empty}");

    let file = path.with_file_name("dynamic.toml");
    let file_arg = file.to_str().expect("UTF-8 path");
    write_certificate(path.parent().expect("directory"), "example");
    let certificate = "[certificates.example]\ncert = \"example.crt\"\nkey = \"example.key\"\n";
    std::fs::write(&file, format!("version = 1\n{certificate}")).expect("write");
    let apply = ["apply", "-f", file_arg, "-m", "from the command line"];
    let (code, out, err) = wormway_config(&path, "cli-token", &apply);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.trim(), "applied: version 1 is in effect");

    let (code, exported, _) = wormway_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(0));
    assert!(exported.contains(certificate), "{exported}");
    std::fs::write(&file, exported).expect("write");
    let (code, out, _) = wormway_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(0));
    assert_eq!(
        out.trim(),
        "no change: these settings are already in effect"
    );

    let (status, body) = get(&addr, "/api/v1/config/versions", Some("cli-token"));
    assert_eq!(status, 200);
    assert!(
        body.contains(r#""source":"cli","comment":"from the command line""#),
        "{body}"
    );
    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
}

/// Problems are reported against the applied file, like `wormway check` does, and nothing is
/// applied: syntax errors before contacting Wormway, rule violations as Wormway reports them.
#[test]
fn reports_problems_with_applied_settings() {
    let (mut wormway, path, _) = start_for_config("config-problems", "cli-token");
    let file = path.with_file_name("dynamic.toml");
    let file_arg = file.to_str().expect("UTF-8 path");
    let file_name = file.display().to_string();

    std::fs::write(&file, "version = 1\n[listeners\n").expect("write");
    let (code, _, err) = wormway_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with(&format!("{file_name}:2:11: error:")),
        "{err}"
    );

    std::fs::write(&file, "version = 1\n[routes.web]\nupstream = \"missing\"\n").expect("write");
    let (code, _, err) = wormway_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(1));
    assert!(
        err.contains(&format!(
            "{file_name}: error: routes.web.upstream: unknown upstream \"missing\""
        )),
        "{err}"
    );

    let (code, _, err) = wormway_config(&path, "wrong-token", &["export"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("missing or wrong token"), "{err}");
    assert!(err.contains("hint: set WORMWAY_ADMIN_TOKEN"), "{err}");

    wormway.signal("TERM");
    assert_eq!(wormway.exit_code(), Some(0));
    let (code, _, err) = wormway_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("cannot reach the Admin API"), "{err}");
}
