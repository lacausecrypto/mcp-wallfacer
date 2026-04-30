use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;
use serde_json::Value;
use std::time::Duration;

#[test]
fn differential_learns_then_reports_schema_violations() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let _ = std::fs::remove_dir_all(workspace_root.join(".wallfacer"));

    let mut learn = cargo_bin_cmd!("wallfacer");
    learn
        .current_dir(&workspace_root)
        .args([
            "differential",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--learn",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .success()
        .stdout(contains("learned"));

    let mut run = cargo_bin_cmd!("wallfacer");
    let output = run
        .current_dir(&workspace_root)
        .args([
            "differential",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--format",
            "json",
            "--seed",
            "42",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let findings: Value = serde_json::from_slice(&output).expect("valid findings JSON");
    let findings = findings.as_array().expect("findings array");
    assert_eq!(findings.len(), 3, "expected exactly 3 schema violations");
    assert!(findings.iter().all(|finding| {
        finding["kind"]["type"]
            .as_str()
            .is_some_and(|kind| kind == "schema_violation")
    }));
}
