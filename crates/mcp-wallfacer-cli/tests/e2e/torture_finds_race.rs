#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::time::Duration;

#[test]
fn torture_finds_counter_race_and_state_leak() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let _ = std::fs::remove_dir_all(workspace_root.join(".wallfacer"));

    let mut race = cargo_bin_cmd!("wallfacer");
    let race_output = race
        .current_dir(&workspace_root)
        .args([
            "torture",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--mode",
            "parallel",
            "--target-tool",
            "counter_inc",
            "--concurrency",
            "100",
            "--duration",
            "5s",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let race_report: Value = serde_json::from_slice(&race_output).expect("race JSON");
    assert!(
        race_report["findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()),
        "expected at least one race finding"
    );

    let mut leak = cargo_bin_cmd!("wallfacer");
    let leak_output = leak
        .current_dir(&workspace_root)
        .args([
            "torture",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--mode",
            "state-leak",
            "--format",
            "json",
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let leak_report: Value = serde_json::from_slice(&leak_output).expect("leak JSON");
    assert_eq!(leak_report["findings"][0]["kind"]["type"], "state_leak");
}
