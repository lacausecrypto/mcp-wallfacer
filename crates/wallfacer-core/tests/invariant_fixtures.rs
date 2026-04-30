//! Phase D acceptance: every YAML fixture in
//! `tests/fixtures/invariants/*.yaml` must parse cleanly under the v2 DSL,
//! and the total number of invariants across them must be at least 30.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use wallfacer_core::property::dsl::parse;

fn fixtures_dir() -> PathBuf {
    // The crate's tests run with CWD = crate root, but the fixtures live at
    // the workspace root. Walk up from CARGO_MANIFEST_DIR to find them.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace layout")
        .join("tests/fixtures/invariants")
}

fn collect_yaml_files() -> Vec<PathBuf> {
    let dir = fixtures_dir();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_fixture_parses() {
    let files = collect_yaml_files();
    assert!(!files.is_empty(), "no invariant fixtures discovered");
    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        if let Err(err) = parse(&source) {
            panic!("{}: {err}", path.display());
        }
    }
}

#[test]
fn total_invariants_meet_phase_d_acceptance_threshold() {
    let files = collect_yaml_files();
    let total: usize = files
        .iter()
        .map(|path| {
            let source = std::fs::read_to_string(path).expect("read fixture");
            parse(&source).expect("parse fixture").invariants.len()
        })
        .sum();
    assert!(
        total >= 30,
        "Phase D acceptance: expected ≥ 30 invariants across fixtures, got {total}"
    );
}

#[test]
fn fixtures_round_trip_through_serde() {
    // Serializing then re-parsing must preserve every invariant. This
    // protects against accidental Serialize / Deserialize drift in the DSL.
    for path in collect_yaml_files() {
        let source = std::fs::read_to_string(&path).expect("read");
        let original = parse(&source).expect("parse");
        let yaml = serde_yaml::to_string(&original).expect("serialize");
        let reparsed = parse(&yaml)
            .unwrap_or_else(|err| panic!("re-parse of {} failed: {err}", path.display()));
        assert_eq!(
            original.invariants.len(),
            reparsed.invariants.len(),
            "{}: invariant count drifted on round-trip",
            path.display()
        );
    }
}
