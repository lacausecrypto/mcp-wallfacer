//! Phase L acceptance: the `stateful` pack's
//! `delete_purges_subsequent_read` sequence catches the state-leak
//! bug planted in `examples/python_server` (record_delete returns ok
//! but never actually deletes; the post-delete record_read still
//! finds the row, which is exactly the contract violation).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn run_pack(pack: &str) -> Value {
    let example_dir = workspace_root().join("examples/python_server");
    let _ = std::fs::remove_dir_all(example_dir.join(".wallfacer"));
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let output = cmd
        .current_dir(&example_dir)
        .args([
            "property", "--pack", pack, "--seed", "0", "--cases", "1", "--format", "json",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&output)
        .unwrap_or_else(|_| panic!("non-JSON stdout from `wallfacer property --pack {pack}`"))
}

#[test]
fn stateful_pack_catches_record_delete_state_leak() {
    let report = run_pack("stateful");
    let findings = report["findings"].as_array().expect("findings array");
    let sequence_failures: Vec<&Value> = findings
        .iter()
        .filter(|f| f["kind"]["type"] == "sequence_failure")
        .collect();
    assert!(
        !sequence_failures.is_empty(),
        "expected at least one SequenceFailure finding from the stateful pack \
         against the python_server fixture, got findings: {findings:?}"
    );
    let first = sequence_failures[0];
    assert_eq!(
        first["kind"]["sequence"].as_str(),
        Some("stateful.delete_purges_subsequent_read"),
        "sequence finding should identify the leaky-delete sequence"
    );
    // The bug shows up at step 2 (the post-delete read): step indices
    // are 0=create, 1=delete, 2=read; the read is `expect: error` but
    // the buggy server returns the row anyway.
    assert_eq!(
        first["kind"]["step_index"].as_u64(),
        Some(2),
        "the post-delete read (step index 2) is the offending step"
    );
    assert_eq!(
        first["kind"]["step_call"].as_str(),
        Some("record_read"),
        "step call should be record_read"
    );
}
