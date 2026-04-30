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
