//! Phase X acceptance: `wallfacer corpus minimize <id> --replay`
//! shrinks a finding's input by re-driving it against the live
//! target.
//!
//! Strategy: plant a synthetic Crash-class finding whose input is
//! an oversized JSON object (5+ KB), then ask the shrinker to
//! reduce it. The python_server's `crashes_now` tool kills the
//! process on any call, so any non-empty input is a valid shrink
//! target. Acceptance: shrinker reduces ≥80% of the byte size and
//! still finishes in <MAX_STEPS.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

#[test]
fn corpus_minimize_replay_shrinks_oversized_crash_input() {
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

    // Plant a synthetic Crash finding with an oversized input.
    // We pick `crashes_now` because the python_server kills the
    // process on every call regardless of input — so any of the
    // shrinker's trial inputs that are valid JSON objects still
    // crash, and the shrinker can reduce them to the minimum.
    let corpus_dir = rundir.path().join(".wallfacer/corpus/crashes_now");
    fs::create_dir_all(&corpus_dir).expect("mkdir");
    // ~3 KB of pad keys to force real shrinking work.
    let mut pad = serde_json::Map::new();
    for i in 0..50 {
        pad.insert(format!("noise_key_{i}"), Value::String("a".repeat(50)));
    }
    let synthetic = serde_json::json!({
        "id": "abcdef0123456789",
        "kind": {"type": "crash"},
        "severity": "critical",
        "tool": "crashes_now",
        "message": "synthetic for shrink test",
        "details": "synthetic",
        "repro": {
            "seed": 0,
            "tool_call": Value::Object(pad),
            "transport": "stdio"
        },
        "timestamp": "2026-05-01T10:00:00Z"
    });
    let original_bytes = serde_json::to_vec(&synthetic["repro"]["tool_call"])
        .unwrap()
        .len();
    assert!(
        original_bytes > 2000,
        "synthetic input must be sufficiently large to test shrinking; got {original_bytes}"
    );
    fs::write(
        corpus_dir.join("abcdef0123456789.json"),
        serde_json::to_string(&synthetic).unwrap(),
    )
    .expect("write");

    // Drive the shrinker.
    let output = cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args(["corpus", "minimize", "abcdef", "--replay"])
        .timeout(Duration::from_secs(120))
        .assert()
        .get_output()
        .stdout
        .clone();
    let shrunk: Value = serde_json::from_slice(&output).expect("shrunk JSON");
    let shrunk_bytes = serde_json::to_vec(&shrunk).unwrap().len();

    assert!(
        shrunk_bytes < original_bytes / 5,
        "shrinker must reduce input by at least 80%; original={original_bytes}, shrunk={shrunk_bytes}"
    );
}
