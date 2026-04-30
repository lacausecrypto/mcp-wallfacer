//! Phase F acceptance: `examples/python_server/` exercises all six
//! [`FindingKind`] variants.
//!
//! This e2e test runs the canonical wallfacer commands against the
//! example server and asserts every kind appears in the corpus at least
//! once.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{collections::HashSet, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn run_wallfacer(args: &[&str], expect_failure: bool) {
    let example_dir = workspace_root().join("examples/python_server");
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let assertion = cmd
        .current_dir(&example_dir)
        .args(args)
        .timeout(Duration::from_secs(60))
        .assert();
    if expect_failure {
        assertion.failure();
    } else {
        assertion.success();
    }
}

#[test]
fn example_server_triggers_every_finding_kind() {
    let example_dir = workspace_root().join("examples/python_server");
    let _ = std::fs::remove_dir_all(example_dir.join(".wallfacer"));

    // Differential first (creates inferred_schemas/ baseline). `--learn`
    // succeeds (no findings); the second `differential` then catches the
    // wrong_id_type schema violation.
    run_wallfacer(&["differential", "--learn"], false);
    run_wallfacer(&["differential", "--seed", "0", "--iterations", "1"], true);

    // Each fuzz invocation targets a single buggy tool to keep the run
    // short and the failure mode unambiguous.
    run_wallfacer(
        &[
            "fuzz",
            "--seed",
            "0",
            "--iterations",
            "1",
            "--include",
            "crashes_now",
        ],
        true,
    );
    run_wallfacer(
        &[
            "fuzz",
            "--seed",
            "0",
            "--iterations",
            "1",
            "--include",
            "hangs_forever",
        ],
        true,
    );
    run_wallfacer(
        &[
            "fuzz",
            "--seed",
            "0",
            "--iterations",
            "1",
            "--include",
            "bad_protocol",
        ],
        true,
    );

    // Property failure on `paginate` (toggle returns limit+1 every other
    // call, so a single case is enough).
    run_wallfacer(
        &["property", "invariants.yaml", "--seed", "0", "--cases", "4"],
        true,
    );

    // State leak: session_set seeds the SESSIONS dict, session_get reads it.
    run_wallfacer(&["torture", "--mode", "state-leak"], true);

    // Walk the corpus and collect every kind we observed.
    let corpus_dir = example_dir.join(".wallfacer/corpus");
    let mut kinds = HashSet::new();
    for entry in walkdir(&corpus_dir) {
        if entry.extension().is_some_and(|ext| ext == "json") {
            let body = std::fs::read_to_string(&entry).expect("read finding");
            let value: Value = serde_json::from_str(&body).expect("finding JSON");
            if let Some(kind) = value["kind"]["type"].as_str() {
                kinds.insert(kind.to_string());
            }
        }
    }
    let expected = [
        "crash",
        "hang",
        "schema_violation",
        "property_failure",
        "protocol_error",
        "state_leak",
    ];
    for kind in expected {
        assert!(
            kinds.contains(kind),
            "expected finding kind `{kind}` in corpus; observed: {kinds:?}"
        );
    }
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walkdir(&path));
        } else {
            out.push(path);
        }
    }
    out
}
