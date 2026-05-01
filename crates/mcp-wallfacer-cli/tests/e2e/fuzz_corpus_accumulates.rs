//! Phase R acceptance: `wallfacer fuzz --corpus-feedback`
//! persists interesting inputs across runs.
//!
//! Drives two independent fuzz runs against the python_server
//! fixture and asserts:
//! 1. The first run produces corpus entries (findings + novel
//!    fingerprints).
//! 2. The second run sees the corpus directory grow (or stay
//!    stable when every fingerprint repeats — at minimum it does
//!    not shrink).
//! 3. Corpus files have the v0.6 entry shape (tool / input /
//!    trigger / fingerprint / timestamp).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, path::PathBuf, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn fuzz(rundir: &std::path::Path, seed: u64, iterations: u64) {
    cargo_bin_cmd!("wallfacer")
        .current_dir(rundir)
        .args([
            "fuzz",
            "--seed",
            &seed.to_string(),
            "--iterations",
            &iterations.to_string(),
            "--corpus-feedback",
            "--include",
            "bug_log",
            "--include",
            "crashes_now",
            "--max-tools",
            "5",
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .get_output();
}

fn count_corpus_entries(rundir: &std::path::Path) -> usize {
    let dir = rundir.join(".wallfacer/fuzz_corpus");
    if !dir.is_dir() {
        return 0;
    }
    let mut count = 0;
    for tool_dir in fs::read_dir(&dir).expect("read corpus") {
        let tool_dir = tool_dir.expect("entry");
        if tool_dir.path().is_dir() {
            for entry in fs::read_dir(tool_dir.path()).expect("read tool dir") {
                let entry = entry.expect("entry");
                if entry.path().extension().is_some_and(|x| x == "json") {
                    count += 1;
                }
            }
        }
    }
    count
}

fn find_one_corpus_file(rundir: &std::path::Path) -> Option<PathBuf> {
    let dir = rundir.join(".wallfacer/fuzz_corpus");
    for tool_dir in fs::read_dir(dir).ok()? {
        let tool_dir = tool_dir.ok()?;
        if tool_dir.path().is_dir() {
            for entry in fs::read_dir(tool_dir.path()).ok()? {
                let entry = entry.ok()?;
                if entry.path().extension().is_some_and(|x| x == "json") {
                    return Some(entry.path());
                }
            }
        }
    }
    None
}

#[test]
fn fuzz_corpus_accumulates_across_runs() {
    let example_dir = workspace_root().join("examples/python_server");
    let rundir = tempfile::tempdir().expect("tempdir");
    fs::write(
        rundir.path().join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "stdio"
command = "python3"
args = ["{}/server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"

[allow_destructive]
tools = ["^crashes_now$"]
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");

    fuzz(rundir.path(), 0, 30);
    let after_first = count_corpus_entries(rundir.path());
    assert!(
        after_first > 0,
        "corpus must have ≥1 entry after a 30-iteration run; got {after_first}"
    );

    fuzz(rundir.path(), 1, 20);
    let after_second = count_corpus_entries(rundir.path());
    assert!(
        after_second >= after_first,
        "corpus must not shrink across runs; first={after_first}, second={after_second}"
    );
}

#[test]
fn corpus_entry_has_phase_r_shape() {
    let example_dir = workspace_root().join("examples/python_server");
    let rundir = tempfile::tempdir().expect("tempdir");
    fs::write(
        rundir.path().join("wallfacer.toml"),
        format!(
            r#"
[target]
kind = "stdio"
command = "python3"
args = ["{}/server.py"]
timeout_ms = 5000

[output]
corpus_dir = ".wallfacer/corpus"

[allow_destructive]
tools = ["^crashes_now$"]
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");
    fuzz(rundir.path(), 0, 30);

    let path = find_one_corpus_file(rundir.path()).expect("at least one corpus entry");
    let bytes = fs::read(&path).expect("read");
    let entry: Value = serde_json::from_slice(&bytes).expect("json");
    assert!(entry["tool"].is_string(), "entry.tool must be a string");
    assert!(
        entry["input"].is_object(),
        "entry.input must be a JSON object"
    );
    assert!(
        entry["trigger"]["type"].is_string(),
        "entry.trigger.type must be a string"
    );
    let fingerprint = entry["fingerprint"].as_str().expect("fingerprint string");
    assert_eq!(
        fingerprint.len(),
        16,
        "fingerprint should be a 16-hex SHA-256 prefix; got {fingerprint:?}"
    );
}
