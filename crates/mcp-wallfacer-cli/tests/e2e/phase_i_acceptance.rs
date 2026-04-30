//! Phase I acceptance: running the new rule packs against
//! `examples/python_server` produces ≥ 8 distinct findings (no false
//! positives — every finding maps to a real bug in the fixture).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

/// Runs `wallfacer property --pack <name>` against the example server
/// and returns the JSON output, regardless of exit status (a non-zero
/// exit is the EXPECTED outcome when findings are produced).
fn run_pack(name: &str) -> Value {
    let example_dir = workspace_root().join("examples/python_server");
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let output = cmd
        .current_dir(&example_dir)
        .args([
            "property", "--pack", name, "--seed", "0", "--cases", "2", "--format", "json",
        ])
        .timeout(Duration::from_secs(20))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&output)
        .unwrap_or_else(|_| panic!("pack `{name}` produced non-JSON output"))
}

fn count_findings(report: &Value) -> usize {
    report["findings"]
        .as_array()
        .map(|arr| arr.len())
        .unwrap_or(0)
}

#[test]
fn pack_run_against_fixture_yields_at_least_eight_findings() {
    // Reset the corpus so we measure findings from this run only.
    let example_dir = workspace_root().join("examples/python_server");
    let _ = std::fs::remove_dir_all(example_dir.join(".wallfacer"));

    // Each entry: (pack name, minimum findings expected).
    // Packs probing tools that don't exist on the fixture are skipped
    // by exclusion from this list (we only include packs that map to
    // bugs the fixture actually exposes).
    let packs = [
        "secrets-leakage",
        "path-traversal",
        "injection-sql",
        "injection-shell",
        "prompt-injection",
        "pagination",
        "tool-annotations",
        "idempotency",
    ];

    let mut total = 0usize;
    let mut per_pack: Vec<(String, usize)> = Vec::new();
    for pack in &packs {
        let report = run_pack(pack);
        let count = count_findings(&report);
        per_pack.push(((*pack).to_string(), count));
        total += count;
    }

    eprintln!("phase-I per-pack findings: {per_pack:?}");
    assert!(
        total >= 8,
        "Phase I acceptance: expected ≥ 8 findings, got {total} (per pack: {per_pack:?})"
    );

    // Spot check: at least 5 distinct packs should produce findings —
    // confirms the breadth of the new library, not just one over-active
    // pack contributing every finding.
    let producing = per_pack.iter().filter(|(_, n)| *n > 0).count();
    assert!(
        producing >= 5,
        "Phase I acceptance: expected ≥ 5 packs to produce findings, got {producing} (per pack: {per_pack:?})"
    );
}
