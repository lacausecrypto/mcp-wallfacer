//! Phase Q acceptance: `wallfacer coverage` produces a static
//! `(tool, pack)` matrix and `--strict` exits non-zero when at least
//! one tool is uncovered.

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

fn run_coverage_json(packs: &[&str]) -> Value {
    let example_dir = workspace_root().join("examples/python_server");
    let mut cmd = cargo_bin_cmd!("wallfacer");
    cmd.current_dir(&example_dir).arg("coverage");
    for p in packs {
        cmd.args(["--pack", p]);
    }
    cmd.args(["--format", "json"]);
    let stdout = cmd
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&stdout).unwrap_or_else(|err| {
        panic!(
            "non-JSON stdout: {err}\n---\n{}",
            String::from_utf8_lossy(&stdout)
        )
    })
}

#[test]
fn coverage_pack_all_covers_every_tool_in_python_server() {
    let example_dir = workspace_root().join("examples/python_server");
    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(&example_dir)
        .args(["coverage", "--format", "json"])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    let m: Value = serde_json::from_slice(&stdout).expect("json");

    let uncovered = m["uncovered_tools"].as_array().unwrap();
    assert!(
        uncovered.is_empty(),
        "with the full embedded pack set, every fixture tool should land in at least one pack; \
         got uncovered: {:?}",
        uncovered
    );
}

#[test]
fn coverage_strict_flag_exits_2_when_tool_uncovered() {
    let example_dir = workspace_root().join("examples/python_server");
    // `auth` pack alone doesn't touch any of the fixture's
    // tools (the fixture has no whoami / login / list_resources).
    // `--strict` with only `auth` should therefore exit non-zero.
    let assert = cargo_bin_cmd!("wallfacer")
        .current_dir(&example_dir)
        .args(["coverage", "--pack", "auth", "--strict"])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure();
    let exit = assert.get_output().status.code();
    assert_eq!(exit, Some(2), "--strict should exit 2 when uncovered");
}

#[test]
fn coverage_stateful_pack_covers_record_triple() {
    let m = run_coverage_json(&["stateful"]);
    let cells = m["cells"].as_object().unwrap();
    assert_eq!(cells["record_create"]["stateful"].as_str(), Some("covered"));
    assert_eq!(cells["record_delete"]["stateful"].as_str(), Some("covered"));
    assert_eq!(cells["record_read"]["stateful"].as_str(), Some("covered"));
    // `bug_log` has no part in the stateful sequence.
    assert_eq!(cells["bug_log"]["stateful"].as_str(), Some("uncovered"));
}
