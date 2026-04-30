//! Phase H acceptance: `wallfacer pack test --all` exits 0 on every
//! shipped pack — every invariant has at least one passing and one
//! failing fixture, and the fixture runner agrees with the assertion
//! evaluator.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn pack_test_all_passes_on_shipped_packs() {
    let mut cmd = cargo_bin_cmd!("wallfacer");
    cmd.args(["pack", "test", "--all"])
        // Run from a tempdir without a wallfacer.toml so we exercise
        // the embedded library only — the production scenario for
        // `pack test --all` in CI.
        .current_dir(std::env::temp_dir())
        .timeout(Duration::from_secs(20))
        .assert()
        .success();
}

#[test]
fn pack_list_lists_three_embedded_packs() {
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let output = cmd
        .args(["pack", "list"])
        .current_dir(std::env::temp_dir())
        .timeout(Duration::from_secs(10))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let body = String::from_utf8_lossy(&output);
    for expected in ["auth", "path-traversal", "error-shape"] {
        assert!(
            body.contains(expected),
            "pack list output should contain `{expected}`; got:\n{body}"
        );
    }
}
