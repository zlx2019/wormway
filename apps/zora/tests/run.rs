//! End-to-end tests of `zora run`: startup, the Admin API, reload on SIGHUP and shutdown on
//! SIGINT or SIGTERM; and of the `zora config` commands against a running zora.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
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

/// Writes `text` as `zora.toml` into a fresh directory named `name` in Cargo's temporary
/// directory for tests, and returns the path of the file. The data directory goes next to it.
fn temp_config(name: &str, text: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the test directory");
    let path = dir.join("zora.toml");
    std::fs::write(&path, text).expect("write the test configuration");
    path
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
        "GET {path} HTTP/1.1\r\nHost: zora\r\n{authorization}Connection: close\r\n\r\n"
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

/// Runs `zora config ARGS -c path` with the Admin API token `token`, and returns the exit
/// code, standard output and standard error.
fn zora_config(path: &Path, token: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_zora"))
        .arg("config")
        .args(args)
        .arg("-c")
        .arg(path)
        .env_remove("ZORA_CONFIG")
        .env("ZORA_ADMIN_TOKEN", token)
        .output()
        .expect("run zora config");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Starts `zora run` in database mode with the Admin API token `token`, and returns it with
/// the address of the Admin API. The `zora config` commands find the API through the file, so
/// the port the API got is written into it.
fn start_for_config(name: &str, token: &str) -> (Zora, PathBuf, String) {
    let path = temp_config(name, &format!("version = 1\n{ADMIN}"));
    let mut zora = Zora::start_with_env(&path, &[("ZORA_ADMIN_TOKEN", token)]);
    let addr = zora.admin_addr();
    zora.wait_for("zora is ready");
    let text = format!("version = 1\n[admin]\nlisten = \"{addr}\"\n");
    std::fs::write(&path, text).expect("write the Admin API address");
    (zora, path, addr)
}

/// A `zora run` process and its log lines.
struct Zora {
    /// The process.
    child: Child,
    /// Lines of standard error, read by a background thread.
    lines: Receiver<String>,
    /// Lines received so far, shown when a wait fails.
    seen: Vec<String>,
}

impl Zora {
    /// Starts `zora run` with the configuration file at `path`.
    fn start(path: &Path) -> Self {
        Self::start_with_env(path, &[])
    }

    /// Starts `zora run` with the configuration file at `path` and extra environment variables.
    fn start_with_env(path: &Path, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zora"))
            .args(["run", "-c"])
            .arg(path)
            .env_remove("ZORA_CONFIG")
            .env_remove("ZORA_ADMIN_TOKEN")
            .envs(env.iter().copied())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start zora");
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
        panic!("zora did not exit, log:\n{}", self.seen.join("\n"));
    }
}

impl Drop for Zora {
    /// Kills the process if a test failed while it was running.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `zora run` starts and stops cleanly on SIGTERM.
#[test]
fn stops_on_sigterm() {
    let mut zora = Zora::start(&temp_config("run-sigterm", EMPTY));
    zora.wait_for("zora is ready");
    zora.signal("TERM");
    zora.wait_for("stopped");
    assert_eq!(zora.exit_code(), Some(0));
}

/// SIGHUP rereads the file. An invalid file is reported and the running configuration stays;
/// changed static settings are only reported.
#[test]
fn reloads_on_sighup() {
    let path = temp_config("run-sighup", EMPTY);
    let mut zora = Zora::start(&path);
    zora.wait_for("zora is ready");

    std::fs::write(&path, format!("{EMPTY}[server]\nthread = 4\n")).expect("write");
    zora.signal("HUP");
    let failed = zora.wait_for("reload failed");
    assert!(failed.contains("unknown field `thread`"), "{failed}");

    std::fs::write(&path, format!("{EMPTY}[server]\nthreads = 4\n")).expect("write");
    zora.signal("HUP");
    zora.wait_for("static settings changed");
    let reloaded = zora.wait_for("configuration reloaded");
    assert!(reloaded.contains("config_version=2"), "{reloaded}");

    zora.signal("INT");
    assert_eq!(zora.exit_code(), Some(0));
}

/// A listener whose protocol is not built in stops startup with an error.
#[test]
fn rejects_unavailable_protocols() {
    let listener = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";
    let mut zora = Zora::start(&temp_config("run-http", &format!("{EMPTY}{listener}")));
    zora.wait_for("listener web: protocol http is not available in this build");
    assert_eq!(zora.exit_code(), Some(1));
}

/// An invalid file is reported like `zora check` does, before anything starts.
#[test]
fn reports_invalid_files() {
    let path = temp_config("run-invalid", "version = 1\n[log]\nlevel = \"info,=x=\"\n");
    let mut zora = Zora::start(&path);
    let line = zora.wait_for("error: log.level: invalid filter directive");
    assert!(line.starts_with(&path.display().to_string()), "{line}");
    assert_eq!(zora.exit_code(), Some(1));
}

/// The Admin API answers health checks without a token and everything else with it. The token
/// file is created on first start, readable by its owner only.
#[test]
fn serves_the_admin_api() {
    let path = temp_config("run-admin", &format!("version = 1\n{ADMIN}"));
    let mut zora = Zora::start(&path);
    let addr = zora.admin_addr();
    zora.wait_for("zora is ready");

    assert_eq!(get(&addr, "/healthz", None).0, 200);
    assert_eq!(get(&addr, "/api/v1/status", None).0, 401);
    let token_file = path.with_file_name("data").join("admin.token");
    let token = std::fs::read_to_string(&token_file).expect("token file");
    let (status, body) = get(&addr, "/api/v1/status", Some(token.trim()));
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(r#""source":"db""#), "{body}");
    let (status, body) = get(&addr, "/metrics", Some(token.trim()));
    assert_eq!(status, 200);
    assert!(body.contains("zora_build_info"), "{body}");

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&token_file)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    zora.signal("TERM");
    assert_eq!(zora.exit_code(), Some(0));
}

/// `ZORA_ADMIN_TOKEN` replaces the token file.
#[test]
fn takes_the_token_from_the_environment() {
    let path = temp_config("run-admin-env", &format!("version = 1\n{ADMIN}"));
    let mut zora = Zora::start_with_env(&path, &[("ZORA_ADMIN_TOKEN", "from-env")]);
    let addr = zora.admin_addr();
    assert_eq!(get(&addr, "/api/v1/status", Some("from-env")).0, 200);
    assert!(!path.with_file_name("data").join("admin.token").exists());
    zora.signal("TERM");
    assert_eq!(zora.exit_code(), Some(0));
}

/// `zora config apply` saves the settings of a file as a version from the command line, and
/// `zora config export` writes them in a form that `apply` reads back.
#[test]
fn applies_and_exports_dynamic_settings() {
    let (mut zora, path, addr) = start_for_config("config-apply", "cli-token");
    let (code, empty, _) = zora_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(0));
    assert!(empty.starts_with("version = 1\n"), "{empty}");

    let file = path.with_file_name("dynamic.toml");
    let file_arg = file.to_str().expect("UTF-8 path");
    let certificate = "[certificates.example]\ncert = \"example.crt\"\nkey = \"example.key\"\n";
    std::fs::write(&file, format!("version = 1\n{certificate}")).expect("write");
    let apply = ["apply", "-f", file_arg, "-m", "from the command line"];
    let (code, out, err) = zora_config(&path, "cli-token", &apply);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out.trim(), "applied: version 1 is in effect");

    let (code, exported, _) = zora_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(0));
    assert!(exported.contains(certificate), "{exported}");
    std::fs::write(&file, exported).expect("write");
    let (code, out, _) = zora_config(&path, "cli-token", &["apply", "-f", file_arg]);
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
    zora.signal("TERM");
    assert_eq!(zora.exit_code(), Some(0));
}

/// Problems are reported against the applied file, like `zora check` does, and nothing is
/// applied: syntax errors before contacting zora, rule violations as zora reports them.
#[test]
fn reports_problems_with_applied_settings() {
    let (mut zora, path, _) = start_for_config("config-problems", "cli-token");
    let file = path.with_file_name("dynamic.toml");
    let file_arg = file.to_str().expect("UTF-8 path");
    let file_name = file.display().to_string();

    std::fs::write(&file, "version = 1\n[listeners\n").expect("write");
    let (code, _, err) = zora_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(1));
    assert!(
        err.starts_with(&format!("{file_name}:2:11: error:")),
        "{err}"
    );

    let listener = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";
    std::fs::write(&file, format!("version = 1\n{listener}")).expect("write");
    let (code, _, err) = zora_config(&path, "cli-token", &["apply", "-f", file_arg]);
    assert_eq!(code, Some(1));
    assert!(
        err.contains(&format!(
            "{file_name}: error: listeners.web.protocol: protocol http is not available"
        )),
        "{err}"
    );

    let (code, _, err) = zora_config(&path, "wrong-token", &["export"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("missing or wrong token"), "{err}");
    assert!(err.contains("hint: set ZORA_ADMIN_TOKEN"), "{err}");

    zora.signal("TERM");
    assert_eq!(zora.exit_code(), Some(0));
    let (code, _, err) = zora_config(&path, "cli-token", &["export"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("cannot reach the Admin API"), "{err}");
}
