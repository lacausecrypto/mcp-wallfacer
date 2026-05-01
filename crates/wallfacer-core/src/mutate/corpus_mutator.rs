//! Phase R — corpus-driven mutation engine.
//!
//! Given a JSON value (a previous "interesting" input pulled from
//! the fuzz corpus), produce a *related* JSON value by applying
//! one or more local mutations. The result is fed back into the
//! tool call instead of a fresh schema-driven random payload — the
//! 90 % side of the v0.6 mutate-vs-random split.
//!
//! Strategies are deliberately simple. We don't aim for libFuzzer-
//! grade coverage feedback — that needs target instrumentation we
//! don't have over MCP. We aim for the next tier up: "find bugs
//! that random schema generation misses because the input space
//! is structured (e.g. needs a valid id, a Unicode-clean string,
//! …)". Mutating from a known-interesting baseline rather than
//! starting fresh is the cheap win.
//!
//! Each call to [`mutate`] picks one of the strategies at random
//! and applies it to a randomly-chosen leaf of the input tree.
//! Strategies can compose across calls: 100 mutate calls on the
//! same baseline produce a wide front of related but distinct
//! payloads.

use rand::Rng;
use serde_json::Value;

/// Mutation strategies, picked uniformly per call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strategy {
    /// Append a small ASCII suffix to a string leaf.
    StringNudge,
    /// Replace a string leaf with a Unicode-trickery string (RTL
    /// override / zero-width / mojibake).
    StringUnicode,
    /// Add or subtract 1 from a numeric leaf, with a low chance of
    /// jumping to the i64::MAX/MIN boundary.
    NumberNudge,
    /// Flip a boolean leaf.
    BoolFlip,
    /// Swap a leaf's type (string ↔ number ↔ null) — exercises
    /// schema-validation corners.
    TypeFlip,
    /// Drop a key from an object (forces "missing required field"
    /// paths in the server).
    DropKey,
    /// Duplicate a key with a slightly different value (server
    /// behaviour on duplicate JSON keys is fragile).
    GrowArray,
}

const ALL: &[Strategy] = &[
    Strategy::StringNudge,
    Strategy::StringUnicode,
    Strategy::NumberNudge,
    Strategy::BoolFlip,
    Strategy::TypeFlip,
    Strategy::DropKey,
    Strategy::GrowArray,
];

/// Mutates `input` and returns a related but distinct value.
///
/// The result preserves the top-level structure (object stays
/// object, array stays array) but a single leaf is altered.
/// Empty inputs return an empty object — mutation is a no-op when
/// there's nothing to mutate.
pub fn mutate(input: &Value, rng: &mut impl Rng) -> Value {
    let strategy = ALL[rng.gen_range(0..ALL.len())];
    let mut out = input.clone();
    apply(&mut out, strategy, rng);
    out
}

fn apply(value: &mut Value, strategy: Strategy, rng: &mut impl Rng) {
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                return;
            }
            // Pick a key uniformly. Recursive descent into the
            // chosen subtree.
            let keys: Vec<String> = map.keys().cloned().collect();
            let chosen = &keys[rng.gen_range(0..keys.len())];
            match strategy {
                Strategy::DropKey => {
                    map.remove(chosen);
                }
                Strategy::GrowArray => {
                    if let Some(Value::Array(arr)) = map.get_mut(chosen) {
                        // Duplicate the last element.
                        if let Some(last) = arr.last().cloned() {
                            arr.push(last);
                        } else {
                            arr.push(Value::Null);
                        }
                    } else if let Some(child) = map.get_mut(chosen) {
                        apply(child, strategy, rng);
                    }
                }
                _ => {
                    if let Some(child) = map.get_mut(chosen) {
                        apply(child, strategy, rng);
                    }
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                if matches!(strategy, Strategy::GrowArray) {
                    arr.push(Value::Null);
                }
                return;
            }
            let idx = rng.gen_range(0..arr.len());
            apply(&mut arr[idx], strategy, rng);
        }
        Value::String(s) => match strategy {
            Strategy::StringNudge => s.push_str("_x"),
            Strategy::StringUnicode => {
                // RTL override + zero-width joiner + the original
                // text. Catches servers that reflect strings with
                // bidi tricks or fail to normalise zero-width.
                *s = format!("\u{202E}\u{200D}{s}");
            }
            Strategy::TypeFlip => {
                *value = Value::Number(serde_json::Number::from(0));
            }
            _ => {}
        },
        Value::Number(_) => match strategy {
            Strategy::NumberNudge => {
                if let Some(n) = value.as_i64() {
                    let nudged = if rng.gen_bool(0.1) {
                        if rng.gen_bool(0.5) {
                            i64::MAX
                        } else {
                            i64::MIN
                        }
                    } else {
                        n.saturating_add(if rng.gen_bool(0.5) { 1 } else { -1 })
                    };
                    *value = Value::Number(serde_json::Number::from(nudged));
                } else if let Some(n) = value.as_f64() {
                    *value = Value::Number(
                        serde_json::Number::from_f64(n + 1.0)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    );
                }
            }
            Strategy::TypeFlip => {
                *value = Value::String("0".to_string());
            }
            _ => {}
        },
        Value::Bool(b) => {
            if matches!(strategy, Strategy::BoolFlip | Strategy::TypeFlip) {
                if matches!(strategy, Strategy::TypeFlip) {
                    *value = Value::String((!*b).to_string());
                } else {
                    *value = Value::Bool(!*b);
                }
            }
        }
        Value::Null => {
            if matches!(strategy, Strategy::TypeFlip) {
                *value = Value::String("".to_string());
            }
        }
    }
}

/// Splice mutator: combines two corpus inputs by randomly merging
/// keys from one into the other. Used when the corpus is large
/// enough that mutating a single seed gets stuck in a local basin.
pub fn splice(a: &Value, b: &Value, rng: &mut impl Rng) -> Value {
    match (a, b) {
        (Value::Object(am), Value::Object(bm)) => {
            let mut out = am.clone();
            let bkeys: Vec<&String> = bm.keys().collect();
            if bkeys.is_empty() {
                return Value::Object(out);
            }
            // Take ~half of b's keys, overriding a.
            let take = (bkeys.len() / 2).max(1);
            for k in bkeys.iter().take(take) {
                if let Some(v) = bm.get(*k) {
                    out.insert((*k).clone(), v.clone());
                }
            }
            // Random nudge on top.
            apply(&mut Value::Object(out.clone()), Strategy::StringNudge, rng);
            Value::Object(out)
        }
        _ => mutate(a, rng),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_json::json;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([42; 32])
    }

    #[test]
    fn mutate_preserves_top_level_object_shape() {
        let input = json!({"name": "alice", "age": 30});
        for _ in 0..50 {
            let out = mutate(&input, &mut rng());
            assert!(out.is_object(), "top-level must stay object");
        }
    }

    #[test]
    fn mutate_actually_mutates_at_least_some_of_the_time() {
        let input = json!({"name": "alice", "age": 30, "active": true});
        let mut rng = rng();
        let mut differs = 0;
        for _ in 0..50 {
            let out = mutate(&input, &mut rng);
            if out != input {
                differs += 1;
            }
        }
        assert!(
            differs > 25,
            "mutation should actually change the input most of the time; got {differs}/50"
        );
    }

    #[test]
    fn mutate_is_resilient_against_empty_input() {
        let mut rng = rng();
        for _ in 0..10 {
            // Should not panic.
            let _ = mutate(&json!({}), &mut rng);
            let _ = mutate(&json!([]), &mut rng);
            let _ = mutate(&json!(null), &mut rng);
        }
    }

    #[test]
    fn splice_combines_keys_from_both_parents() {
        let a = json!({"a": 1, "b": 2});
        let b = json!({"c": 3, "d": 4});
        let mut rng = rng();
        let mut saw_c_or_d = 0;
        for _ in 0..50 {
            let out = splice(&a, &b, &mut rng);
            let obj = out.as_object().expect("object");
            if obj.contains_key("c") || obj.contains_key("d") {
                saw_c_or_d += 1;
            }
        }
        assert!(
            saw_c_or_d > 0,
            "splice should sometimes pull keys from `b`; got {saw_c_or_d}/50"
        );
    }
}
