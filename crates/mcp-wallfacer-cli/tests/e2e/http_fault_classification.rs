//! Phase W acceptance: `wallfacer fuzz` correctly classifies
//! HTTP-level faults emitted by a misbehaving server / proxy
//! (502, mid-stream FIN, slow response) as findings without
//! crashing the run.
//!
//! Drives the Phase-W fault-injection fixture
//! (`examples/python_server/server_http_faulty.py`) configured for
//! one fault mode per test, then asserts:
//! 1. The run does not panic / segfault.
//! 2. At least one finding lands of the expected kind class
//!    (`protocol_error` / `hang`).
//! 3. The findings JSON envelope is valid (downstream consumers
//!    keep working under faults).

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

struct Fixture {
    child: Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_faulty_fixture(mode: &str) -> (Fixture, u16) {
    let server = workspace_root().join("examples/python_server/server_http_faulty.py");
    let mut child = Command::new("python3")
        .arg(server)
        .arg("0")
        .arg("--fault-mode")
        .arg(mode)
        .arg("--fault-rate")
        .arg("1.0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 must be on PATH");
    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("port line");
    let port: u16 = line.trim().parse().expect("numeric port");
    (Fixture { child }, port)
}

fn run_fuzz_once(rundir: &std::path::Path, port: u16) -> Value {
    fs::write(
        rundir.join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "http"
url = "http://127.0.0.1:{port}/mcp"
timeout_ms = 4000

[output]
corpus_dir = ".wallfacer/corpus"

[allow_destructive]
tools = ["^crashes_now$", "^record_delete$"]
"#
        ),
    )
    .expect("write toml");
    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir)
        .args([
            "fuzz",
            "--seed",
            "0",
            "--iterations",
            "3",
            "--max-tools",
            "3",
            "--include",
            "bug_log",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&stdout)
        .unwrap_or_else(|_| panic!("non-JSON stdout: {}", String::from_utf8_lossy(&stdout)))
}

#[test]
fn fuzz_under_502_classifies_as_protocol_error() {
    let (fixture, port) = spawn_faulty_fixture("502");
    let _guard = fixture;
    let rundir = tempfile::tempdir().expect("tempdir");
    let report = run_fuzz_once(rundir.path(), port);
    let kinds: Vec<String> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["kind"]["type"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|k| k == "protocol_error"),
        "expected at least one ProtocolError finding under 502 fault, got {kinds:?}"
    );
}

#[test]
fn fuzz_under_fin_mid_classifies_as_hang_or_protocol_error() {
    let (fixture, port) = spawn_faulty_fixture("fin-mid");
    let _guard = fixture;
    let rundir = tempfile::tempdir().expect("tempdir");
    let report = run_fuzz_once(rundir.path(), port);
    let kinds: Vec<String> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["kind"]["type"].as_str().map(|s| s.to_string()))
        .collect();
    // Either the rmcp client times out reading the truncated body
    // (Hang) or it surfaces an explicit transport error
    // (ProtocolError). Both are acceptable classifications — the
    // contract is "produces a finding, doesn't crash".
    assert!(
        kinds.iter().any(|k| k == "hang" || k == "protocol_error"),
        "expected Hang or ProtocolError under fin-mid fault, got {kinds:?}"
    );
}

#[test]
fn fuzz_under_fin_empty_classifies_finding() {
    let (fixture, port) = spawn_faulty_fixture("fin-empty");
    let _guard = fixture;
    let rundir = tempfile::tempdir().expect("tempdir");
    let report = run_fuzz_once(rundir.path(), port);
    let kinds: Vec<String> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|f| f["kind"]["type"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|k| k == "hang" || k == "protocol_error"),
        "expected Hang or ProtocolError under fin-empty fault, got {kinds:?}"
    );
}
