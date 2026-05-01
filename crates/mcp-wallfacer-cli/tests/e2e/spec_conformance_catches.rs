//! Phase S acceptance: the `mcp-spec-conformance` pack catches MCP
//! spec violations on the python_server fixture.
//!
//! The fixture has `list_active_users` declared as
//! `idempotentHint: true` but its envelope omits `isError` and
//! `structuredContent` — a clear spec violation. The pack extends
//! `idempotency` so the findings stream from there.

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
fn mcp_spec_conformance_catches_idempotency_envelope_violation() {
    let report = run_pack_json("mcp-spec-conformance");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "expected `mcp-spec-conformance` to fire on the fixture's malformed `list_active_users` envelope"
    );
    let invariants: Vec<String> = findings
        .iter()
        .filter_map(|f| f["kind"]["invariant"].as_str().map(|s| s.to_string()))
        .collect();
    let touches_list_active_users = invariants
        .iter()
        .any(|name| name.contains("list_active_users"));
    assert!(
        touches_list_active_users,
        "expected at least one finding on `list_active_users`, got {invariants:?}"
    );
}

#[test]
fn mcp_spec_conformance_pack_is_listed_in_wallfacer_pack_list() {
    let stdout = cargo_bin_cmd!("wallfacer")
        .args(["pack", "list"])
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("mcp-spec-conformance"),
        "embedded pack list must include `mcp-spec-conformance`; got:\n{text}"
    );
    assert!(
        text.contains("context-poisoning"),
        "embedded pack list must include `context-poisoning`; got:\n{text}"
    );
}
