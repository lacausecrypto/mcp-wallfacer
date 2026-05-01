//! Phase P acceptance: `wallfacer suggest` proposes the right packs
//! against the python_server fixture, with parameters pre-filled
//! from the observable tool catalog.
//!
//! The fixture exposes a deliberate buggy zoo of tools (`bug_log`,
//! `read_file`, `query_db`, `run_shell`, `ask_llm`, `record_create`,
//! `record_read`, `record_delete`, ...) — each one is a textbook
//! match for a different pack. The test asserts the engine's output
//! includes those packs and pre-fills the parameters that the run-
//! command would otherwise take from a hand-edited `wallfacer.toml`.

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

fn run_suggest_json() -> Vec<Value> {
    let example_dir = workspace_root().join("examples/python_server");
    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(&example_dir)
        .args(["suggest", "--format", "json"])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    let value: Value =
        serde_json::from_slice(&stdout).expect("suggest --format json must produce valid JSON");
    value.as_array().cloned().expect("top-level array")
}

#[test]
fn suggest_proposes_all_obvious_packs_for_python_server() {
    let suggestions = run_suggest_json();
    let pack_names: std::collections::BTreeSet<String> = suggestions
        .iter()
        .filter_map(|s| s["pack"].as_str().map(|p| p.to_string()))
        .collect();

    // Must catch every "textbook" match the fixture plants.
    for expected in [
        "error-shape",
        "injection-shell",
        "injection-sql",
        "path-traversal",
        "prompt-injection",
        "secrets-leakage",
        "stateful",
        "tool-annotations",
        "unicode",
        "large-payload",
    ] {
        assert!(
            pack_names.contains(expected),
            "expected pack `{expected}` in suggestions; got {:?}",
            pack_names
        );
    }
}

#[test]
fn suggest_pre_fills_stateful_triple_from_record_tools() {
    let suggestions = run_suggest_json();
    let stateful = suggestions
        .iter()
        .find(|s| s["pack"] == "stateful")
        .expect("stateful pack must be suggested");
    let overrides = &stateful["param_overrides"];
    assert_eq!(overrides["create_tool"], "record_create");
    assert_eq!(overrides["read_tool"], "record_read");
    assert_eq!(overrides["delete_tool"], "record_delete");
}

#[test]
fn suggest_pre_fills_path_traversal_tool_for_read_file() {
    let suggestions = run_suggest_json();
    let pt = suggestions
        .iter()
        .find(|s| s["pack"] == "path-traversal")
        .expect("path-traversal must be suggested");
    assert_eq!(pt["witness_tool"], "read_file");
    assert_eq!(pt["param_overrides"]["read_file_tool"], "read_file");
}

#[test]
fn suggest_pre_fills_injection_shell_tool_for_run_shell() {
    let suggestions = run_suggest_json();
    let s = suggestions
        .iter()
        .find(|s| s["pack"] == "injection-shell")
        .expect("injection-shell must be suggested");
    assert_eq!(s["witness_tool"], "run_shell");
    assert_eq!(s["param_overrides"]["shell_tool"], "run_shell");
    assert_eq!(s["param_overrides"]["shell_field"], "command");
}
