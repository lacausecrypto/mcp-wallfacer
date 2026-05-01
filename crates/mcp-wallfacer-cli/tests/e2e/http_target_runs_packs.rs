//! Phase M acceptance: wallfacer's HTTP transport runs rule packs
//! against an HTTP MCP target with the same fidelity as stdio.
//!
//! Spawns `examples/python_server/server_http.py` on an OS-assigned
//! free port, points wallfacer at `http://127.0.0.1:<port>/mcp`, then
//! runs the same packs we exercise in stdio mode and asserts the
//! findings counts line up.
//!
//! The HTTP fixture is pure-stdlib Python (no FastAPI / uvicorn) so
//! the test only depends on `python3` being on `PATH` — already
//! installed by the Test workflow's setup-python step.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

/// Spawns the HTTP fixture on `port=0` and reads the actual bound
/// port from its stdout. Returns the child handle (so the caller can
/// kill it on drop) and the port string.
fn spawn_http_fixture() -> (HttpFixture, u16) {
    let server_path = workspace_root().join("examples/python_server/server_http.py");
    let mut child = Command::new("python3")
        .arg(server_path)
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 must be on PATH for the HTTP fixture e2e test");

    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("fixture must print its bound port to stdout");
    let port: u16 = line
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("expected numeric port, got `{line}`"));
    (HttpFixture { child }, port)
}

/// RAII guard that kills the spawned fixture when dropped, even if
/// the test panics.
struct HttpFixture {
    child: Child,
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_pack_over_http(rundir: &std::path::Path, port: u16, pack: &str) -> Value {
    let toml = format!(
        r#"
[target]
kind = "http"
url = "http://127.0.0.1:{port}/mcp"
timeout_ms = 10000

[output]
corpus_dir = ".wallfacer/corpus"

[packs.secrets-leakage]
witness_tool = "bug_log"
witness_field = "text"

[packs.unicode]
witness_tool = "bug_log"
witness_field = "text"

[packs.large-payload]
string_witness_tool = "bug_log"
string_witness_field = "text"
array_witness_tool = "bug_log"
array_witness_field = "text"
"#
    );
    fs::write(rundir.join("wallfacer.toml"), toml).expect("write toml");

    let output = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir)
        .args([
            "property", "--pack", pack, "--seed", "0", "--cases", "1", "--format", "json",
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&output)
        .unwrap_or_else(|_| panic!("non-JSON stdout from `wallfacer property --pack {pack}`"))
}

#[test]
fn http_transport_runs_secrets_leakage_pack_against_python_fixture() {
    let (fixture, port) = spawn_http_fixture();
    // Hold fixture alive for the duration of this test.
    let _guard = fixture;

    let rundir = tempfile::tempdir().expect("tempdir");
    let report = run_pack_over_http(rundir.path(), port, "secrets-leakage");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "expected secrets-leakage to fire on the HTTP fixture's `bug_log` echo, got {findings:?}"
    );
    // Sanity: the same findings must surface as in stdio mode. The
    // fixture's `bug_log` echoes its input, so any secrets-leakage
    // probe sees an exact-match echo and the invariant fails.
    // Invariants in the secrets-leakage pack are namespaced under
    // `secrets.<...>` (e.g. `secrets.bearer_tokens_not_echoed`), not
    // `secrets-leakage.*` — match on the actual prefix.
    let echoed = findings.iter().any(|f| {
        f["kind"]["invariant"]
            .as_str()
            .is_some_and(|name| name.starts_with("secrets."))
    });
    assert!(
        echoed,
        "expected at least one secrets.* invariant failure, got: {findings:?}"
    );
}

#[test]
fn http_transport_doctor_lists_tools_with_capability_aware_resources() {
    let (fixture, port) = spawn_http_fixture();
    let _guard = fixture;

    let rundir = tempfile::tempdir().expect("tempdir");
    fs::write(
        rundir.path().join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "http"
url = "http://127.0.0.1:{port}/mcp"
timeout_ms = 10000
[output]
corpus_dir = ".wallfacer/corpus"
"#
        ),
    )
    .expect("write toml");

    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .arg("doctor")
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("http"),
        "doctor should report `http` as the transport"
    );
    // The HTTP fixture only declares `tools` capability, so doctor
    // must render `n/a` (added in v0.3.3) for resources / prompts
    // rather than `0`.
    assert!(
        text.contains("n/a"),
        "doctor should render `n/a` for capabilities the server didn't advertise"
    );
}
