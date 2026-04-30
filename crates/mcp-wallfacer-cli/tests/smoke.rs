use assert_cmd::cargo::cargo_bin_cmd;

#[test]
fn version_prints_package_version() {
    let mut cmd = cargo_bin_cmd!("wallfacer");

    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("0.1.0"));
}
