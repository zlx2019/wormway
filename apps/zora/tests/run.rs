//! End-to-end tests of `zora run`: startup, reload on SIGHUP and shutdown on SIGINT or SIGTERM.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// How long to wait for a log line or for the process to exit.
const PATIENCE: Duration = Duration::from_secs(10);

/// File mode without listeners: starts with every binary build.
const EMPTY: &str = "version = 1\n[config]\nsource = \"file\"\n";

/// Writes `text` to a file named `name` in Cargo's temporary directory for tests.
fn temp_config(name: &str, text: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, text).expect("write the test configuration");
    path
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_zora"))
            .args(["run", "-c"])
            .arg(path)
            .env_remove("ZORA_CONFIG")
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
    let mut zora = Zora::start(&temp_config("run-sigterm.toml", EMPTY));
    zora.wait_for("zora is ready");
    zora.signal("TERM");
    zora.wait_for("stopped");
    assert_eq!(zora.exit_code(), Some(0));
}

/// SIGHUP rereads the file. An invalid file is reported and the running configuration stays;
/// changed static settings are only reported.
#[test]
fn reloads_on_sighup() {
    let path = temp_config("run-sighup.toml", EMPTY);
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
    let mut zora = Zora::start(&temp_config("run-http.toml", &format!("{EMPTY}{listener}")));
    zora.wait_for("listener web: protocol http is not available in this build");
    assert_eq!(zora.exit_code(), Some(1));
}

/// An invalid file is reported like `zora check` does, before anything starts.
#[test]
fn reports_invalid_files() {
    let path = temp_config(
        "run-invalid.toml",
        "version = 1\n[log]\nlevel = \"info,=x=\"\n",
    );
    let mut zora = Zora::start(&path);
    let line = zora.wait_for("error: log.level: invalid filter directive");
    assert!(line.starts_with(&path.display().to_string()), "{line}");
    assert_eq!(zora.exit_code(), Some(1));
}
