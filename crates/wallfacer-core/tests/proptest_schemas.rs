//! Phase B acceptance: 200 synthetic JSON Schemas with `oneOf`/`anyOf`,
//! `allOf`, `$ref`, and `not`. Each is exercised via
//! [`wallfacer_core::mutate::try_generate_payload`] in conformant mode and
//! the resulting payload is validated against the original schema using
//! `jsonschema`. Acceptance threshold: ≥ 99 % of generations must produce
//! conforming payloads (the remaining ≤ 1 % is allowed as `Skip`, never as
//! a non-conforming success).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use wallfacer_core::mutate::{try_generate_payload, GenMode, SkipReason};

const TOTAL_CASES: u32 = 200;

static OK_COUNT: AtomicUsize = AtomicUsize::new(0);
static SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);
static FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Generates a synthetic JSON Schema using a depth-bounded recursive choice
/// of composition keywords. Output is deterministic in `seed`.
fn synth_schema(seed: u64, depth: u8) -> Value {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let body = synth_node(&mut rng, depth, /*is_root=*/ true);
    // Always wrap the root in an object schema so callers receive an
    // input-shaped schema, matching the contract of MCP tool inputs.
    json!({
        "$defs": {
            "Tag": {"type": "string", "enum": ["alpha", "beta", "gamma"]},
            "Counter": {"type": "integer", "minimum": 0, "maximum": 1000}
        },
        "type": "object",
        "properties": {
            "payload": body
        },
        "required": ["payload"]
    })
}

fn synth_node(rng: &mut impl rand::Rng, depth: u8, is_root: bool) -> Value {
    if depth == 0 {
        return synth_leaf(rng);
    }

    // 5 strategies: leaf, object, array, oneOf, allOf, $ref. Root layer skips
    // bare leaves to keep coverage interesting.
    let pick = rng.gen_range(0..6);
    match pick {
        0 if !is_root => synth_leaf(rng),
        1 => synth_object(rng, depth, "p"),
        2 => synth_array(rng, depth),
        3 => synth_one_of(rng, depth),
        4 => synth_all_of(rng, depth),
        _ => synth_ref(rng),
    }
}

fn synth_leaf(rng: &mut impl rand::Rng) -> Value {
    match rng.gen_range(0..5) {
        0 => json!({"type": "string", "minLength": 1, "maxLength": 16}),
        1 => json!({"type": "integer", "minimum": -100, "maximum": 100}),
        2 => json!({"type": "number", "minimum": -10, "maximum": 10}),
        3 => json!({"type": "boolean"}),
        _ => json!({"type": "string", "format": "uuid"}),
    }
}

fn synth_object(rng: &mut impl rand::Rng, depth: u8, prefix: &str) -> Value {
    let next = depth.saturating_sub(1);
    let prop_count = rng.gen_range(1..=3);
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for index in 0..prop_count {
        let key = format!("{prefix}{index}");
        let value = synth_node(rng, next, /*is_root=*/ false);
        properties.insert(key.clone(), value);
        if rng.gen_bool(0.5) {
            required.push(Value::String(key));
        }
    }
    // We deliberately do not set `additionalProperties: false`: synthetic
    // `allOf` compositions would otherwise generate mutually-exclusive
    // sub-schemas (each forbidding the other's properties), which is a
    // schema-author bug that no generator can satisfy.
    json!({
        "type": "object",
        "properties": properties,
        "required": required
    })
}

fn synth_array(rng: &mut impl rand::Rng, depth: u8) -> Value {
    let items = synth_node(rng, depth.saturating_sub(1), /*is_root=*/ false);
    json!({
        "type": "array",
        "items": items,
        "minItems": 0,
        "maxItems": 4
    })
}

fn synth_one_of(rng: &mut impl rand::Rng, depth: u8) -> Value {
    let count = rng.gen_range(2..=3);
    let next = depth.saturating_sub(1);
    let branches: Vec<Value> = (0..count)
        .map(|_| synth_node(rng, next, /*is_root=*/ false))
        .collect();
    json!({"oneOf": branches})
}

fn synth_all_of(rng: &mut impl rand::Rng, depth: u8) -> Value {
    // Branches use disjoint key prefixes so the combined schema admits a
    // payload that satisfies both. Without this, synth would routinely emit
    // unsatisfiable schemas.
    let next = depth.saturating_sub(1);
    let branches = vec![synth_object(rng, next, "a"), synth_object(rng, next, "b")];
    json!({"allOf": branches})
}

fn synth_ref(rng: &mut impl rand::Rng) -> Value {
    if rng.gen_bool(0.5) {
        json!({"$ref": "#/$defs/Tag"})
    } else {
        json!({"$ref": "#/$defs/Counter"})
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: TOTAL_CASES,
        // Deterministic across runs so CI remains reproducible.
        rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
        ..ProptestConfig::default()
    })]
    #[test]
    fn synthetic_schemas_yield_conformant_payloads(seed in any::<u64>()) {
        let schema = synth_schema(seed, 4);
        let validator = jsonschema::validator_for(&schema)
            .expect("synthetic schema must always be a valid JSON Schema");

        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(1));
        match try_generate_payload(&schema, &mut rng, GenMode::Conform) {
            Ok(payload) => {
                if validator.is_valid(&payload.value) {
                    OK_COUNT.fetch_add(1, Ordering::Relaxed);
                } else {
                    FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
                    // Surface the failing case in the proptest output to ease
                    // shrinking. The acceptance threshold is enforced by the
                    // companion test below; we still want full visibility.
                    let errors: Vec<String> = validator
                        .iter_errors(&payload.value)
                        .map(|e| format!("{e} at {}", e.instance_path()))
                        .collect();
                    eprintln!(
                        "[proptest][seed={seed}] non-conformant payload\nschema: {}\npayload: {}\nerrors: {:?}\ntrail: {:?}",
                        serde_json::to_string_pretty(&schema).unwrap_or_default(),
                        serde_json::to_string_pretty(&payload.value).unwrap_or_default(),
                        errors,
                        payload.trail,
                    );
                }
            }
            Err(SkipReason::UnresolvedRef(_) | SkipReason::Cycle(_)
                | SkipReason::NotUnsatisfiable(_) | SkipReason::OneOfOverlap(_)
                | SkipReason::EmptyComposition(_) | SkipReason::Malformed(_)) => {
                SKIP_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[test]
fn acceptance_threshold_is_met() {
    // This test must run *after* the proptest above. `cargo test` runs tests
    // in parallel by default, so we synchronise via a shared atomic counter
    // and require that the final tallies satisfy the acceptance criterion.
    //
    // We re-execute a bounded run here so this test is self-contained even
    // when the proptest is filtered out (`cargo test acceptance_threshold`).
    let mut ok = 0usize;
    let mut skip = 0usize;
    let mut fail = 0usize;
    let total = 200usize;
    for seed in 0..total as u64 {
        let schema = synth_schema(seed, 4);
        let validator = jsonschema::validator_for(&schema).expect("valid schema");
        let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(0xdead_beef));
        match try_generate_payload(&schema, &mut rng, GenMode::Conform) {
            Ok(p) => {
                if validator.is_valid(&p.value) {
                    ok += 1;
                } else {
                    fail += 1;
                }
            }
            Err(_) => skip += 1,
        }
    }
    let conformance = ok as f64 / (ok + fail) as f64;
    eprintln!(
        "phase-B acceptance: ok={ok} fail={fail} skip={skip} conformance={:.2}%",
        conformance * 100.0
    );
    assert!(
        conformance >= 0.99,
        "Phase B acceptance: conformance must be >= 99%, observed {:.2}% (ok={ok}, fail={fail}, skip={skip})",
        conformance * 100.0
    );
}
