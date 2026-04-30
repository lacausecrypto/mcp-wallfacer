use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

#[test]
fn property_reports_single_paginate_failure() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let _ = std::fs::remove_dir_all(workspace_root.join(".wallfacer"));

    let mut cmd = cargo_bin_cmd!("wallfacer");
    let output = cmd
        .current_dir(&workspace_root)
        .args([
            "property",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--format",
            "json",
            "--seed",
            "42",
            "tests/fixtures/invariants_sample.yaml",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let findings: Value = serde_json::from_slice(&output).expect("valid findings JSON");
    let findings = findings.as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "expected exactly 1 property finding");
    assert_eq!(findings[0]["tool"], "paginate");
    assert_eq!(findings[0]["kind"]["type"], "property_failure");
}
