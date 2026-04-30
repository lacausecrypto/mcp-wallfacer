use assert_cmd::Command;

#[test]
fn version_prints_package_version() {
    let mut cmd = Command::cargo_bin("wallfacer").expect("wallfacer binary");

    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("0.1.0"));
}
