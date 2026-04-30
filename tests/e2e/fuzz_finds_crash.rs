use assert_cmd::Command;

#[test]
fn fuzz_finds_multiple_bug_classes() {
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let corpus_dir = workspace_root.join(".wallfacer");
    let _ = std::fs::remove_dir_all(&corpus_dir);

    let mut cmd = Command::cargo_bin("wallfacer").expect("wallfacer binary");
    cmd.current_dir(&workspace_root)
        .args([
            "fuzz",
            "--config",
            "tests/fixtures/wallfacer.toml",
            "--seed",
            "42",
            "--iterations",
            "500",
        ])
        .assert()
        .failure();

    let finding_count = count_json_files(&workspace_root.join(".wallfacer/corpus"));
    assert!(
        finding_count >= 3,
        "expected at least 3 findings, got {finding_count}"
    );
}

fn count_json_files(path: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };

    entries
        .flatten()
        .map(|entry| entry.path())
        .map(|path| {
            if path.is_dir() {
                count_json_files(&path)
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                1
            } else {
                0
            }
        })
        .sum()
}
