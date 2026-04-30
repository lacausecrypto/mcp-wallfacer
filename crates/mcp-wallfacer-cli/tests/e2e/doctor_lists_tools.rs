use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

#[test]
fn doctor_lists_echo_tool() {
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    cmd.current_dir(workspace_root)
        .args(["doctor", "--config", "tests/fixtures/wallfacer.toml"])
        .assert()
        .success()
        .stdout(contains("echo"));
}
