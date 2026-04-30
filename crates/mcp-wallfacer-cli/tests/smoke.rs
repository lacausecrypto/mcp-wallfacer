#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_package_version() {
    let mut cmd = cargo_bin_cmd!("wallfacer");

    // Don't pin to a specific version: any non-empty `mcp-wallfacer X.Y.Z`
    // prefix is fine. This keeps the smoke test stable across version bumps.
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::starts_with("mcp-wallfacer "));
}
