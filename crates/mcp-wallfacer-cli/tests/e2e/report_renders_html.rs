//! Phase U acceptance: `wallfacer report --html` renders a
//! self-contained HTML dashboard from the corpus persisted by a
//! prior `wallfacer property` run.
//!
//! Strategy: run a pack against the python_server fixture so the
//! corpus has known findings, then invoke `report` and assert the
//! generated HTML mentions the expected sections + finding tools.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn run_property_to_seed_corpus(rundir: &std::path::Path) {
    cargo_bin_cmd!("wallfacer")
        .current_dir(rundir)
        .args([
            "property",
            "--pack",
            "secrets-leakage",
            "--seed",
            "0",
            "--cases",
            "1",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output();
}

#[test]
fn report_html_includes_summary_and_findings_sections() {
    let example_dir = workspace_root().join("examples/python_server");
    // Use a tempdir-like path under the example to avoid polluting
    // the developer's local .wallfacer.
    let rundir_storage = tempfile::tempdir().expect("tempdir");
    let rundir = rundir_storage.path().to_path_buf();
    fs::write(
        rundir.join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "stdio"
command = "python3"
args = ["{}/server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"

[packs.secrets-leakage]
witness_tool = "bug_log"
witness_field = "text"
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");
    run_property_to_seed_corpus(&rundir);

    let out = rundir.join("report.html");
    cargo_bin_cmd!("wallfacer")
        .current_dir(&rundir)
        .args(["report", "--out", out.to_str().unwrap()])
        .timeout(Duration::from_secs(30))
        .assert()
        .success();
    let html = fs::read_to_string(&out).expect("read report");

    assert!(html.contains("<!DOCTYPE html>"), "must be a real HTML doc");
    assert!(html.contains("Summary"), "summary section present");
    assert!(html.contains("Findings"), "findings section present");
    assert!(
        html.contains("bug_log"),
        "fixture's witness tool must appear in the report"
    );
    // Inline CSS must be present (no external assets in the
    // generated dashboard).
    assert!(html.contains("<style>"), "inline CSS expected");
    // No JS — keeps the dashboard email-friendly.
    assert!(
        !html.contains("<script"),
        "report must be JS-free for offline / email use"
    );
}

#[test]
fn report_html_escapes_user_supplied_strings() {
    // Render a report from an in-memory corpus to verify that user
    // strings in `details` / `message` get HTML-escaped, even when
    // the operator hand-edits a corpus file. We do this by writing
    // a synthetic finding directly to disk.
    let rundir = tempfile::tempdir().expect("tempdir");
    let corpus_dir = rundir.path().join(".wallfacer/corpus/x");
    fs::create_dir_all(&corpus_dir).expect("mkdir");
    let synthetic = serde_json::json!({
        "id": "deadbeef00000000",
        "kind": {"type": "crash"},
        "severity": "critical",
        "tool": "x",
        "message": "<script>alert('xss')</script>",
        "details": "<img src=x onerror=alert(1)>",
        "repro": {
            "seed": 0,
            "tool_call": {},
            "transport": "stdio"
        },
        "timestamp": "2026-05-01T08:00:00Z"
    });
    fs::write(
        corpus_dir.join("deadbeef00000000.json"),
        serde_json::to_string(&synthetic).unwrap(),
    )
    .expect("write finding");

    let out = rundir.path().join("report.html");
    cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "report",
            "--corpus",
            rundir.path().join(".wallfacer/corpus").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .success();
    let html = fs::read_to_string(&out).expect("read");
    assert!(
        !html.contains("<script>alert"),
        "user strings must be escaped"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "expected entity-encoded form"
    );
}
