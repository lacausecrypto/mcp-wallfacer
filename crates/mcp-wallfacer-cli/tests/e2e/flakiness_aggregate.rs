//! Phase AC.2 acceptance: `wallfacer fuzz --runs N --aggregate`
//! produces a flakiness-tagged report.
//!
//! Drives the python_server fixture's `crashes_now` tool which
//! crashes deterministically. Across N runs, the same `Finding::id`
//! should appear N times → labeled `stable`. The aggregate JSON
//! envelope shape is asserted so downstream consumers (CI gates,
//! dashboards) keep working.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, path::PathBuf, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

#[test]
fn fuzz_runs_aggregate_tags_stable_crash() {
    let example_dir = workspace_root().join("examples/python_server");
    let rundir = tempfile::tempdir().expect("tempdir");
    fs::write(
        rundir.path().join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "stdio"
command = "python3"
args = ["{}/server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"

[allow_destructive]
tools = ["^crashes_now$"]
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");

    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "fuzz",
            "--seed",
            "1",
            "--iterations",
            "3",
            "--include",
            "crashes_now",
            "--runs",
            "3",
            "--aggregate",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .failure() // exits 1 because findings > 0
        .get_output()
        .stdout
        .clone();

    let report: Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|_| panic!("non-JSON stdout: {}", String::from_utf8_lossy(&stdout)));
    assert_eq!(report["runs"], 3, "runs field must reflect --runs");
    let aggregate = report["aggregate"]
        .as_array()
        .expect("aggregate field must be an array");
    assert!(
        !aggregate.is_empty(),
        "aggregate must not be empty when crashes_now fired"
    );
    // crashes_now is deterministic — every run should hit it, so
    // at least one entry should be tagged `stable`.
    let stable_crash = aggregate.iter().find(|entry| {
        entry["tool"] == "crashes_now"
            && entry["kind"] == "crash"
            && entry["label"] == "stable"
            && entry["occurrences"] == 3
    });
    assert!(
        stable_crash.is_some(),
        "expected a stable crashes_now/crash entry in aggregate, got {aggregate:?}"
    );
}

#[test]
fn fuzz_runs_one_disables_aggregate() {
    // `--aggregate` requires `--runs >= 2`; passing it with the
    // default runs=1 should bail with a clear error rather than
    // silently producing an empty aggregate.
    let example_dir = workspace_root().join("examples/python_server");
    let rundir = tempfile::tempdir().expect("tempdir");
    fs::write(
        rundir.path().join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "stdio"
command = "python3"
args = ["{}/server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");

    let stderr = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "fuzz",
            "--seed",
            "1",
            "--iterations",
            "1",
            "--include",
            "bug_log",
            "--aggregate",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let text = String::from_utf8_lossy(&stderr);
    assert!(
        text.contains("--aggregate") && text.contains("--runs"),
        "expected --aggregate / --runs guidance, got: {text}"
    );
}
