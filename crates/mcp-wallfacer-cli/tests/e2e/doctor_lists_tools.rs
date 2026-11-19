#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;
use std::time::Duration;

#[test]
fn doctor_lists_echo_tool() {
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    cmd.current_dir(workspace_root)
        .args(["doctor", "--config", "tests/fixtures/wallfacer.toml"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success()
        .stdout(contains("echo"));
}

/// Campaign regression: servers that declare the `resources` / `prompts`
/// capability but answer `-32601 Method not found` made `doctor` abort,
/// so the target looked like it never started. `doctor` must still list
/// the tools, mark the broken listing as `error`, and explain why.
#[test]
fn doctor_survives_declared_but_unimplemented_listings() {
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    cmd.current_dir(workspace_root)
        .env("WALLFACER_FIXTURE_UNIMPLEMENTED_LISTS", "1")
        .args(["doctor", "--config", "tests/fixtures/wallfacer.toml"])
        .timeout(Duration::from_secs(20))
        .assert()
        .success()
        .stdout(contains("echo"))
        .stdout(contains("error"))
        .stderr(contains("declares the `resources` capability"))
        .stderr(contains("-32601"));
}
