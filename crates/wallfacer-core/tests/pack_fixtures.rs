//! Phase G acceptance: every shipped pack under `packs/*.yaml` parses
//! cleanly under the v3 templating pipeline, every declared parameter
//! has a description, and the round-trip through serde is idempotent.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{collections::BTreeMap, path::PathBuf};

use wallfacer_core::property::dsl::{parse, parse_with_overrides};

fn packs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("packs")
}

fn collect_packs() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(packs_dir())
        .expect("packs directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_pack_parses_with_default_parameters() {
    let packs = collect_packs();
    assert!(!packs.is_empty(), "no packs discovered");
    for path in &packs {
        let source = std::fs::read_to_string(path).expect("read");
        if let Err(err) = parse(&source) {
            panic!("{}: {err}", path.display());
        }
    }
}

#[test]
fn every_pack_declares_v3_metadata() {
    for path in collect_packs() {
        let source = std::fs::read_to_string(&path).expect("read");
        let file = parse(&source).expect("parse");
        assert_eq!(
            file.version,
            3,
            "{}: expected version 3, got {}",
            path.display(),
            file.version
        );
        let metadata = file
            .metadata
            .as_ref()
            .unwrap_or_else(|| panic!("{}: missing metadata block", path.display()));
        assert!(
            metadata.name.is_some(),
            "{}: metadata.name is required",
            path.display()
        );
        assert!(
            metadata.description.is_some(),
            "{}: metadata.description is required",
            path.display()
        );
        assert!(
            !metadata.tags.is_empty(),
            "{}: metadata.tags must list at least one tag",
            path.display()
        );
    }
}

#[test]
fn every_parameter_carries_a_description() {
    // Phase G acceptance: the user-facing rationale for parameter
    // overrides is the description string. Refuse to ship a parameter
    // without one — silent params are a UX trap.
    for path in collect_packs() {
        let source = std::fs::read_to_string(&path).expect("read");
        let file = parse(&source).expect("parse");
        let Some(metadata) = file.metadata else {
            continue;
        };
        for (key, param) in &metadata.parameters {
            assert!(
                param.description.is_some(),
                "{}: parameter `{key}` is missing a description",
                path.display()
            );
        }
    }
}

#[test]
fn pack_round_trips_through_serde() {
    for path in collect_packs() {
        let source = std::fs::read_to_string(&path).expect("read");
        let original = parse(&source).expect("parse");
        let yaml = serde_yaml::to_string(&original).expect("serialize");
        let reparsed = parse(&yaml).unwrap_or_else(|err| {
            panic!(
                "re-parse of {} after serde round-trip: {err}",
                path.display()
            )
        });
        assert_eq!(
            original.invariants.len(),
            reparsed.invariants.len(),
            "{}: invariant count drifted on round-trip",
            path.display()
        );
        let m1 = original.metadata.unwrap();
        let m2 = reparsed.metadata.unwrap();
        assert_eq!(m1.name, m2.name);
        assert_eq!(m1.parameters.len(), m2.parameters.len());
    }
}

#[test]
fn pack_overrides_substitute_in_tool_field() {
    // Pick the auth pack and override its `whoami_tool` parameter; the
    // first invariant ("auth.unauthenticated_requests_are_rejected")
    // must end up calling our overridden tool name.
    let path = packs_dir().join("auth.yaml");
    let source = std::fs::read_to_string(&path).expect("read auth.yaml");
    let mut overrides = BTreeMap::new();
    overrides.insert("whoami_tool".to_string(), "getCurrentUser".to_string());
    let file = parse_with_overrides(&source, &overrides).expect("parse with override");
    let target_invariant = file
        .invariants
        .iter()
        .find(|i| i.name == "auth.unauthenticated_requests_are_rejected")
        .expect("expected auth.unauthenticated_requests_are_rejected");
    assert_eq!(target_invariant.tool, "getCurrentUser");
}
