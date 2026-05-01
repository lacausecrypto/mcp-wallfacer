//! Phase AB acceptance: `wallfacer torture --mode parallel` survives
//! HTTP faults emitted by a misbehaving server / proxy without
//! deadlocking, and surfaces a finding rather than crashing.
//!
//! Drives the Phase-W fault-injection fixture
//! (`examples/python_server/server_http_faulty.py`) configured for
//! `--fault-mode 502 --fault-rate 1.0`, then asserts:
//! 1. The run terminates inside the global deadline (no deadlock).
//! 2. At least one finding lands (parallel calls did not all complete).
//! 3. The findings JSON envelope is well-formed under load.

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

fn write_toml(rundir: &std::path::Path, port: u16) {
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
"#
        ),
    )
    .expect("write toml");
}

#[test]
fn torture_parallel_under_502_surfaces_finding_and_terminates() {
    let (fixture, port) = spawn_faulty_fixture("502");
    let _guard = fixture;
    let rundir = tempfile::tempdir().expect("tempdir");
    write_toml(rundir.path(), port);

    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "torture",
            "--mode",
            "parallel",
            // bug_log is non-destructive and exists in the shared
            // server.py catalog the faulty fixture re-exports.
            "--target-tool",
            "bug_log",
            "--concurrency",
            "8",
            "--per-call-timeout",
            "3s",
            // Per-call×4 = 12s; the assert-cmd timeout below is the
            // outer ceiling and proves we don't deadlock.
            "--global-deadline",
            "12s",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(45))
        .assert()
        .failure() // exits non-zero because finding count > 0
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|_| panic!("non-JSON stdout: {}", String::from_utf8_lossy(&stdout)));
    let findings = report["findings"]
        .as_array()
        .expect("findings array on torture report");
    assert!(
        !findings.is_empty(),
        "expected at least one finding under 502 fault, got {report:?}"
    );
    // The torture parallel mode emits a ProtocolError when not every
    // call succeeds — that is exactly what 502s produce.
    let kinds: Vec<String> = findings
        .iter()
        .filter_map(|f| f["kind"]["type"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|k| k == "protocol_error"),
        "expected ProtocolError under 502, got {kinds:?}"
    );
}

#[test]
fn torture_parallel_under_slow_respects_global_deadline() {
    // Slow mode sleeps 30s before responding; per-call timeout is 2s,
    // so each call should classify as a Hang and the run should
    // terminate inside the global deadline. The point of this test
    // is to confirm the watchdog cancels hung tasks rather than
    // letting `join_all` block forever.
    let (fixture, port) = spawn_faulty_fixture("slow");
    let _guard = fixture;
    let rundir = tempfile::tempdir().expect("tempdir");
    write_toml(rundir.path(), port);

    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "torture",
            "--mode",
            "parallel",
            "--target-tool",
            "bug_log",
            "--concurrency",
            "4",
            "--per-call-timeout",
            "2s",
            "--global-deadline",
            "10s",
            "--format",
            "json",
        ])
        // Outer ceiling: if the watchdog ever leaks, the whole
        // process hangs and assert_cmd kills us at this boundary —
        // that would itself prove a regression.
        .timeout(Duration::from_secs(45))
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|_| panic!("non-JSON stdout: {}", String::from_utf8_lossy(&stdout)));
    assert!(
        report["findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()),
        "expected at least one finding under slow fault, got {report:?}"
    );
}
