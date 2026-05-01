//! Phase T acceptance: the `context-poisoning` pack catches the
//! malicious-server bugs planted in the python_server fixture.
//!
//! Two distinct surfaces are tested:
//! - `poisoned_helper` — a tool whose *description* contains a
//!   prompt injection ("Ignore all previous instructions...") +
//!   an exfiltration URL.
//! - `poisoned_response` — a tool whose *response* contains agent
//!   role-override markers (`<|system|>`).
//!
//! The pack uses Phase T's new `$.tool` assertion context, so a
//! find here also gates that DSL extension.

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

fn run_pack_json(pack: &str) -> Value {
    let example_dir = workspace_root().join("examples/python_server");
    let _ = std::fs::remove_dir_all(example_dir.join(".wallfacer"));
    let stdout = cargo_bin_cmd!("wallfacer")
        .current_dir(&example_dir)
        .args([
            "property", "--pack", pack, "--seed", "0", "--cases", "1", "--format", "json",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&stdout)
        .unwrap_or_else(|_| panic!("non-JSON stdout for `wallfacer property --pack {pack}`"))
}

#[test]
fn context_poisoning_catches_description_injection() {
    let report = run_pack_json("context-poisoning");
    let findings = report["findings"].as_array().expect("findings array");
    let invariants: Vec<String> = findings
        .iter()
        .filter_map(|f| f["kind"]["invariant"].as_str().map(|s| s.to_string()))
        .collect();

    // The poisoned_helper tool's description contains "Ignore all
    // previous instructions" — must trip the description-side
    // injection check.
    let trigger = invariants.iter().find(|name| {
        name.contains("tool_description_no_ignore_previous") && name.contains("poisoned_helper")
    });
    assert!(
        trigger.is_some(),
        "expected a description-injection finding on `poisoned_helper`, got {invariants:?}"
    );
}

#[test]
fn context_poisoning_catches_exfil_url_in_description() {
    let report = run_pack_json("context-poisoning");
    let findings = report["findings"].as_array().expect("findings array");
    let invariants: Vec<String> = findings
        .iter()
        .filter_map(|f| f["kind"]["invariant"].as_str().map(|s| s.to_string()))
        .collect();
    let trigger = invariants.iter().find(|name| {
        name.contains("tool_description_no_exfil_url") && name.contains("poisoned_helper")
    });
    assert!(
        trigger.is_some(),
        "expected an exfil-URL finding on `poisoned_helper`, got {invariants:?}"
    );
}

#[test]
fn context_poisoning_catches_role_override_in_response() {
    let report = run_pack_json("context-poisoning");
    let findings = report["findings"].as_array().expect("findings array");
    let invariants: Vec<String> = findings
        .iter()
        .filter_map(|f| f["kind"]["invariant"].as_str().map(|s| s.to_string()))
        .collect();
    let trigger = invariants.iter().find(|name| {
        name.contains("response_no_role_override") && name.contains("poisoned_response")
    });
    assert!(
        trigger.is_some(),
        "expected a role-override finding on `poisoned_response`, got {invariants:?}"
    );
}
