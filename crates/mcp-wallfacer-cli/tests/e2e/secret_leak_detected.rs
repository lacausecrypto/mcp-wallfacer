#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! End-to-end check of the canary secret: wallfacer plants
//! `WALLFACER_CANARY_SECRET` in the environment of the stdio server it
//! spawns, and reports a response that discloses it.

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::time::Duration;

fn fuzz_json(include: &str, leak_env: bool) -> (bool, Value) {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cmd = cargo_bin_cmd!("wallfacer");
    cmd.current_dir(&workspace_root).args([
        "fuzz",
        "--config",
        "tests/fixtures/wallfacer.toml",
        "--seed",
        "1",
        "--iterations",
        "3",
        "--mode",
        "conform",
        "--include",
        include,
        "--format",
        "json",
    ]);
    if leak_env {
        cmd.env("WALLFACER_FIXTURE_LEAK_ENV", "1");
    }
    let output = cmd.timeout(Duration::from_secs(30)).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("fuzz --format json is not JSON ({err}): {stdout}"));
    (output.status.success(), json)
}

fn kinds(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("no `findings` array in {report}"))
        .iter()
        .map(|f| f["kind"]["type"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn environment_dump_is_reported_as_secret_leak() {
    let (success, report) = fuzz_json("show_config", true);
    assert!(!success, "a leak must fail the run: {report}");
    assert_eq!(kinds(&report), vec!["secret_leak".to_string()], "{report}");
    let finding = &report["findings"][0];
    assert_eq!(finding["severity"], "critical");
    assert!(finding["details"]
        .as_str()
        .unwrap()
        .contains("WALLFACER_CANARY_SECRET"));
}

/// The fixture `echo` tool reflects its input verbatim: that is not a
/// leak, whatever the input looks like.
#[test]
fn input_reflection_is_not_a_secret_leak() {
    let (_, report) = fuzz_json("echo", true);
    assert!(
        !kinds(&report).iter().any(|kind| kind == "secret_leak"),
        "{report}"
    );
}
