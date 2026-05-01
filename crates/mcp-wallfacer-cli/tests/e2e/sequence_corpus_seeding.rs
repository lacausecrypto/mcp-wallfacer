//! Phase V acceptance: `wallfacer property --pack stateful
//! --corpus-feedback` grows the persistent fuzz corpus across
//! runs. Each step's response fingerprint feeds the corpus, and
//! the failing step's input is saved under a `Finding` trigger.
//!
//! This is the cross-pollination contract: a fuzz-discovered
//! "interesting input" can seed a sequence's create_tool step on
//! a later run, and a sequence-failure input feeds back into the
//! fuzz pool.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{fs, path::PathBuf, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn write_toml(rundir: &std::path::Path) {
    let example_dir = workspace_root().join("examples/python_server");
    fs::write(
        rundir.join("wallfacer.toml"),
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
tools = ["^crashes_now$", "^record_delete$"]

[packs.stateful]
create_tool = "record_create"
delete_tool = "record_delete"
read_tool = "record_read"
"#,
            example_dir.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write toml");
}

fn run_property_with_corpus(rundir: &std::path::Path, seed: u64) {
    cargo_bin_cmd!("wallfacer")
        .current_dir(rundir)
        .args([
            "property",
            "--pack",
            "stateful",
            "--seed",
            &seed.to_string(),
            "--cases",
            "1",
            "--corpus-feedback",
            "--mutate-ratio",
            "0.0", // disable mutation for deterministic test (use literal substituted input)
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .get_output();
}

fn count_corpus(rundir: &std::path::Path) -> usize {
    let dir = rundir.join(".wallfacer/fuzz_corpus");
    if !dir.is_dir() {
        return 0;
    }
    let mut count = 0;
    if let Ok(iter) = fs::read_dir(&dir) {
        for tool_dir in iter.flatten() {
            if tool_dir.path().is_dir() {
                if let Ok(entries) = fs::read_dir(tool_dir.path()) {
                    count += entries
                        .flatten()
                        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                        .count();
                }
            }
        }
    }
    count
}

#[test]
fn sequence_corpus_grows_with_corpus_feedback_flag() {
    let rundir = tempfile::tempdir().expect("tempdir");
    write_toml(rundir.path());

    run_property_with_corpus(rundir.path(), 0);
    let after_first = count_corpus(rundir.path());
    assert!(
        after_first > 0,
        "expected sequence corpus to gain at least one entry on first run; got {after_first}"
    );
    // The state-leak finding is deterministic on the python_server
    // fixture (record_delete is a no-op), so the failing read_tool
    // step's input must land under a `record_read/*.json` file.
    let read_dir = rundir.path().join(".wallfacer/fuzz_corpus/record_read");
    assert!(
        read_dir.is_dir(),
        "expected per-tool subdir for record_read after a stateful pack run"
    );
    let read_entries: Vec<PathBuf> = fs::read_dir(&read_dir)
        .expect("read")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    assert!(
        !read_entries.is_empty(),
        "record_read corpus must have at least one entry (the failing post-delete read)"
    );
}

#[test]
fn sequence_corpus_does_not_grow_without_corpus_feedback_flag() {
    // Mirror of the above without --corpus-feedback: the corpus
    // directory must not be created, leaving zero state on disk.
    let rundir = tempfile::tempdir().expect("tempdir");
    write_toml(rundir.path());
    cargo_bin_cmd!("wallfacer")
        .current_dir(rundir.path())
        .args([
            "property", "--pack", "stateful", "--seed", "0", "--cases", "1",
        ])
        .timeout(Duration::from_secs(60))
        .assert()
        .get_output();
    let count = count_corpus(rundir.path());
    assert_eq!(
        count, 0,
        "without --corpus-feedback the fuzz corpus must stay at zero entries; got {count}"
    );
}
