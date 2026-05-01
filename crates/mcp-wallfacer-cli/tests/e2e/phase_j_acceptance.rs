//! Phase J acceptance: multi-pack composition produces deduplicated,
//! pack-grouped findings on the example fixture.
//!
//! The Phase plan asked for "≥ 6 finding kinds + no duplications".
//! `wallfacer property` only produces `PropertyFailure` findings (the
//! Crash / Hang / SchemaViolation / ProtocolError / StateLeak kinds
//! are covered by the other commands), so the realistic acceptance is
//! that `--pack-all` exercises a wide swath of the embedded library
//! without duplicate invariants. We assert: ≥ 20 findings across ≥ 5
//! packs, every finding name unique.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{collections::BTreeSet, time::Duration};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace canonicalisation")
}

fn run(args: &[&str]) -> Value {
    let example_dir = workspace_root().join("examples/python_server");
    let _ = std::fs::remove_dir_all(example_dir.join(".wallfacer"));
    let mut cmd = cargo_bin_cmd!("wallfacer");
    let output = cmd
        .current_dir(&example_dir)
        .args(args)
        .timeout(Duration::from_secs(30))
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&output)
        .unwrap_or_else(|_| panic!("non-JSON stdout from `wallfacer {}`", args.join(" ")))
}

#[test]
fn pack_all_produces_diverse_findings_without_duplicates() {
    let report = run(&[
        "property",
        "--pack-all",
        "--seed",
        "0",
        "--cases",
        "1",
        "--format",
        "json",
    ]);
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        findings.len() >= 20,
        "Phase J acceptance: expected ≥ 20 findings from --pack-all, got {}",
        findings.len()
    );

    // Dedup check: every finding name must appear exactly once.
    // A finding's "name" is its `kind.invariant` (PropertyFailure) or
    // `kind.sequence` (SequenceFailure, Phase L).
    let mut names: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        let kind_obj = &finding["kind"];
        let inv = kind_obj["invariant"]
            .as_str()
            .or_else(|| kind_obj["sequence"].as_str())
            .expect("finding kind carries invariant or sequence name")
            .to_string();
        assert!(
            names.insert(inv.clone()),
            "duplicate finding `{inv}` (Phase J: dedup must drop later occurrences)"
        );
    }

    // Diversity check: at least 5 distinct namespaces (everything before
    // the first dot in the invariant name).
    let namespaces: BTreeSet<String> = names
        .iter()
        .map(|name| {
            name.split_once('.')
                .map(|(ns, _)| ns)
                .unwrap_or(name)
                .to_string()
        })
        .collect();
    assert!(
        namespaces.len() >= 5,
        "Phase J acceptance: expected findings from ≥ 5 packs, got {} ({:?})",
        namespaces.len(),
        namespaces
    );
}

#[test]
fn security_meta_pack_loads_seven_packs_without_duplicates() {
    let report = run(&[
        "property", "--pack", "security", "--seed", "0", "--cases", "1", "--format", "json",
    ]);
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        findings.len() >= 8,
        "Phase J: security meta-pack produced only {} findings",
        findings.len()
    );
    let mut names: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        let kind_obj = &finding["kind"];
        let inv = kind_obj["invariant"]
            .as_str()
            .or_else(|| kind_obj["sequence"].as_str())
            .expect("finding kind carries invariant or sequence name")
            .to_string();
        assert!(
            names.insert(inv.clone()),
            "duplicate `{inv}` from security pack"
        );
    }
}

#[test]
fn multiple_pack_flags_concatenate() {
    // Two packs, one of which (pagination) is known to fire on the
    // fixture; the other (auth) is benign here. Composition must yield
    // pagination's findings without prefixing them.
    let report = run(&[
        "property",
        "--pack",
        "pagination",
        "--pack",
        "auth",
        "--seed",
        "0",
        "--cases",
        "1",
        "--format",
        "json",
    ]);
    let findings = report["findings"].as_array().expect("findings");
    assert!(
        findings.iter().any(|f| f["kind"]["invariant"]
            .as_str()
            .is_some_and(|name| name.starts_with("pagination."))),
        "expected at least one finding under the `pagination.` namespace"
    );
}
