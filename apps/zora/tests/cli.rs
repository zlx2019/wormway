//! End-to-end tests of the `zora` command line.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Outcome of one run of the binary.
struct Run {
    /// Exit code, `None` if the process was killed by a signal.
    code: Option<i32>,
    /// Standard output.
    stdout: String,
    /// Standard error.
    stderr: String,
}

/// Runs the `zora` binary with `args`, ignoring the caller's `ZORA_CONFIG`.
fn zora<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_zora"))
        .args(args)
        .env_remove("ZORA_CONFIG")
        .output()
        .expect("run zora");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Runs `zora check` on `path`.
fn check(path: &Path) -> Run {
    zora([OsStr::new("check"), OsStr::new("-c"), path.as_os_str()])
}

/// Path of a file in the repository root.
fn repo_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name)
}

/// Writes `text` to a file named `name` in Cargo's temporary directory for tests.
fn temp_config(name: &str, text: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, text).expect("write the test configuration");
    path
}

/// The committed `zora.schema.json` matches the schema generated from the code.
#[test]
fn schema_file_is_up_to_date() {
    let run = zora(["schema"]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let committed = std::fs::read_to_string(repo_file("zora.schema.json")).expect("read schema");
    // A plain assert, so a mismatch does not print both schemas in full.
    assert!(
        run.stdout == committed,
        "zora.schema.json is out of date, regenerate it with `cargo run -p zora -- schema > zora.schema.json`"
    );
}

/// The example configuration is valid and produces no warnings.
#[test]
fn example_config_is_valid() {
    let run = check(&repo_file("zora.example.toml"));
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stderr, "");
}

/// A parse error is reported as `file:line:column`.
#[test]
fn parse_error_has_a_location() {
    let path = temp_config("parse-error.toml", "version = 1\n[server]\nthread = 4\n");
    let run = check(&path);
    assert_eq!(run.code, Some(1));
    let expected = format!("{}:3:1: error: unknown field `thread`", path.display());
    assert!(run.stderr.starts_with(&expected), "{}", run.stderr);
}

/// Every validation problem is reported in one run, each with the path of its setting.
#[test]
fn reports_every_problem() {
    let path = temp_config(
        "invalid.toml",
        r#"version = 1
[config]
source = "file"
[listeners.a]
listen = []
protocol = "http"
[listeners.b]
listen = ["127.0.0.1:9090"]
protocol = "http"
tls = { certificates = ["missing"] }
"#,
    );
    let run = check(&path);
    assert_eq!(run.code, Some(1));
    let file = path.display();
    let expected = format!(
        "{file}: error: listeners.a.listen: must list at least one address
{file}: error: listeners.b.tls.certificates[0]: unknown certificate \"missing\"
{file}: error: listeners.b.listen[0]: 127.0.0.1:9090 overlaps admin.listen (127.0.0.1:9090)
{file}: 3 error(s)
"
    );
    assert_eq!(run.stderr, expected);
}

/// A valid file with ignored settings passes with a warning.
#[test]
fn warnings_do_not_fail_the_check() {
    let path = temp_config(
        "db-mode.toml",
        "version = 1\n[listeners.web]\nlisten = [\"0.0.0.0:8080\"]\nprotocol = \"http\"\n",
    );
    let run = check(&path);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stderr.contains("warning: listeners: ignored"),
        "{}",
        run.stderr
    );
}

/// A missing file is an error with a readable message.
#[test]
fn missing_file_fails() {
    let run = check(Path::new("does-not-exist.toml"));
    assert_eq!(run.code, Some(1));
    assert!(
        run.stderr.contains("cannot read does-not-exist.toml"),
        "{}",
        run.stderr
    );
}
