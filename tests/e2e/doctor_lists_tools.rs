use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn doctor_lists_echo_tool() {
    let mut cmd = Command::cargo_bin("wallfacer").expect("wallfacer binary");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    cmd.current_dir(workspace_root)
        .args(["doctor", "--config", "tests/fixtures/wallfacer.toml"])
        .assert()
        .success()
        .stdout(contains("echo"));
}
