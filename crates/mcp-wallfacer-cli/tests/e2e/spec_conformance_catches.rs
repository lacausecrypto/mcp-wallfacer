//! Phase S acceptance: the `mcp-spec-conformance` pack catches MCP
//! spec violations on the python_server fixture.
//!
//! The fixture has `list_active_users` declared as
//! `idempotentHint: true` but its envelope carries `isError` as the
//! string `"false"` — a spec violation (an *absent* `isError` /
//! `structuredContent` is valid and must not fire). The client rejects
//! the envelope, so the finding is a `protocol_error` on that tool.

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
        "expected `mcp-spec-conformance` to fire on the fixture's string-typed `isError` on `list_active_users`"
    );
    // rmcp refuses to deserialise a non-boolean `isError`, so the
    // violation surfaces as a protocol error on that tool. Before
    // v0.8.2 the property runner rewrote it into `isError: true` and
    // the run reported nothing.
    let on_tool: Vec<&Value> = findings
        .iter()
        .filter(|f| f["tool"] == "list_active_users")
        .collect();
    assert!(
        on_tool
            .iter()
            .any(|f| f["kind"]["type"] == "protocol_error"),
        "expected a protocol_error finding on `list_active_users`, got {findings:?}"
    );
}
