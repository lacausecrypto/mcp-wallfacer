//! Phase X — input shrinker.
//!
//! Given a JSON input that triggers a particular finding kind on
//! a tool, return the smallest input that still triggers the
//! same finding kind. We approximate "smallest" via a delta-debug
//! style greedy: try simpler variants of the current candidate,
//! keep any that still reproduces, repeat to fixed point.
//!
//! The shrinker is library code: it takes a closure `still_fires`
//! that the caller wires to a real reproduction loop (`replay`,
//! a synchronous test, …). That keeps this module pure and
//! transport-agnostic — any caller that can re-run an input and
//! report yes/no can drive shrinking.
//!
//! Strategies, in the order they're applied each pass:
//!
//! 1. Drop one object key at a time.
//! 2. Empty out a string field (`"abc" → ""`).
//! 3. Halve a string field (`"abcdef" → "abc"`).
//! 4. Drop one array element at a time.
//! 5. Replace a number with `0`.
//! 6. Replace `true` / `false` with `null`-equivalent (`false`,
//!    most servers treat as default).
//!
//! Each pass tries every candidate transformation and keeps the
//! first one that still triggers. We loop until no transformation
//! shrinks the input further (fixed point) or until we hit a
//! configurable iteration cap.

use serde_json::{Map, Value};

use crate::{client::CallOutcome, finding::FindingKind};

/// Coarse class of outcome we're shrinking towards. The CLI
/// classifies the original finding into one of these buckets and
/// the shrink predicate accepts any candidate whose call outcome
/// falls into the same bucket. Tighter classification (e.g.
/// matching the exact error message of a PropertyFailure) is left
/// to the operator's invariant logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkTargetKind {
    /// Original finding was a Crash. Predicate matches when the
    /// candidate makes the server crash.
    Crash,
    /// Original finding was a Hang. Predicate matches when the
    /// candidate produces a Hang outcome (timeout).
    Hang,
    /// Original finding was a ProtocolError. Predicate matches
    /// when the candidate produces a ProtocolError outcome.
    ProtocolError,
    /// Original finding's kind doesn't have a clean transport-
    /// level signal (PropertyFailure / SchemaViolation /
    /// SequenceFailure). The shrinker treats *any* non-clean
    /// outcome (anything except `Ok`) as "still firing" — wide
    /// net, but a real shrink is still better than no shrink.
    AnyNonOk,
}

impl ShrinkTargetKind {
    /// Maps a [`FindingKind`] to the shrink-predicate bucket.
    pub fn from_finding_kind(kind: &FindingKind) -> Self {
        match kind {
            FindingKind::Crash => Self::Crash,
            FindingKind::Hang { .. } => Self::Hang,
            FindingKind::ProtocolError => Self::ProtocolError,
            _ => Self::AnyNonOk,
        }
    }

    /// Returns `true` when `outcome` matches this bucket — i.e.
    /// the candidate input still triggers the same kind of fault.
    pub fn matches_outcome(self, outcome: &CallOutcome) -> bool {
        match (self, outcome) {
            (Self::Crash, CallOutcome::Crash(_)) => true,
            (Self::Hang, CallOutcome::Hang(_)) => true,
            (Self::ProtocolError, CallOutcome::ProtocolError(_)) => true,
            (Self::AnyNonOk, CallOutcome::Ok(_)) => false,
            (Self::AnyNonOk, _) => true,
            _ => false,
        }
    }
}

/// Attempt budget for a single shrink call. Each "step" is one
/// trial transformation + one `still_fires` invocation, so the
/// upper bound on calls is `MAX_STEPS`. 256 is enough for inputs
/// up to ~50 keys deep with multiple shrinkable leaves; the cap
/// stops pathological inputs from spinning forever.
pub const MAX_STEPS: usize = 256;

/// Outcome of one [`shrink`] run.
#[derive(Debug, Clone)]
pub struct ShrinkResult {
    /// Smallest input that still triggers the predicate. Equal
    /// to the original when no shrinking was possible.
    pub minimised: Value,
    /// Number of `still_fires` invocations spent. Useful for
    /// reporters ("shrunk in 17 steps").
    pub steps: usize,
    /// Size delta: `(original_bytes, minimised_bytes)`. Both are
    /// the canonical-JSON byte length, comparable across runs.
    pub byte_size: (usize, usize),
}

/// Greedy delta-debug shrinker (sync). The closure receives a
/// candidate input and returns `true` when it still triggers the
/// finding the caller is shrinking. Pure-CPU shrinker — for the
/// async / live-replay variant, see [`shrink_async`].
///
/// `original` is preserved unchanged on the way in. The returned
/// `minimised` is `original` (cloned) when no transformation
/// reduced the input.
pub fn shrink<F>(original: &Value, mut still_fires: F) -> ShrinkResult
where
    F: FnMut(&Value) -> bool,
{
    let original_bytes = canonical_bytes(original);
    let mut candidate = original.clone();
    let mut steps = 0usize;
    let mut progress = true;
    while progress && steps < MAX_STEPS {
        progress = false;
        let trials = enumerate_trials(&candidate);
        for trial in trials {
            if steps >= MAX_STEPS {
                break;
            }
            steps += 1;
            if still_fires(&trial) {
                candidate = trial;
                progress = true;
                break; // restart with the smaller candidate
            }
        }
    }
    let minimised_bytes = canonical_bytes(&candidate);
    ShrinkResult {
        minimised: candidate,
        steps,
        byte_size: (original_bytes, minimised_bytes),
    }
}

/// Async variant: each trial is verified by an awaited future.
/// Used by `wallfacer corpus minimize` when the predicate is a
/// real `client.call_tool(...)` round-trip.
///
/// Behaviour identical to [`shrink`] otherwise — same MAX_STEPS
/// cap, same enumeration order, same fixed-point termination.
pub async fn shrink_async<F, Fut>(original: &Value, mut still_fires: F) -> ShrinkResult
where
    F: FnMut(Value) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let original_bytes = canonical_bytes(original);
    let mut candidate = original.clone();
    let mut steps = 0usize;
    let mut progress = true;
    while progress && steps < MAX_STEPS {
        progress = false;
        let trials = enumerate_trials(&candidate);
        for trial in trials {
            if steps >= MAX_STEPS {
                break;
            }
            steps += 1;
            if still_fires(trial.clone()).await {
                candidate = trial;
                progress = true;
                break;
            }
        }
    }
    let minimised_bytes = canonical_bytes(&candidate);
    ShrinkResult {
        minimised: candidate,
        steps,
        byte_size: (original_bytes, minimised_bytes),
    }
}

/// Returns every "one-step-smaller" candidate that the shrinker
/// considers in a single pass. Public for tests; the live call
/// path goes through [`shrink`].
pub fn enumerate_trials(value: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    enumerate_at(value, &mut out, &[]);
    out
}

/// Walks `value` in pre-order. For each node `n`, emit candidates
/// where `n` is replaced by a smaller variant. The path is unused
/// for now — it's kept so a future debug build can surface "we
/// shrunk `$.users[0].email`" in the reporter.
fn enumerate_at(value: &Value, out: &mut Vec<Value>, _path: &[String]) {
    match value {
        Value::Object(map) => {
            // Drop a key.
            for key in map.keys() {
                let mut clone = map.clone();
                clone.shift_remove(key);
                out.push(Value::Object(clone));
            }
            // Recurse into each child.
            for (key, child) in map {
                let mut child_trials = Vec::new();
                enumerate_at(child, &mut child_trials, _path);
                for trial in child_trials {
                    let mut clone = map.clone();
                    clone.insert(key.clone(), trial);
                    out.push(Value::Object(clone));
                }
            }
        }
        Value::Array(arr) => {
            // Drop one element at a time.
            for i in 0..arr.len() {
                let mut clone = arr.clone();
                clone.remove(i);
                out.push(Value::Array(clone));
            }
            // Recurse into each element.
            for (i, child) in arr.iter().enumerate() {
                let mut child_trials = Vec::new();
                enumerate_at(child, &mut child_trials, _path);
                for trial in child_trials {
                    let mut clone = arr.clone();
                    clone[i] = trial;
                    out.push(Value::Array(clone));
                }
            }
        }
        Value::String(s) => {
            // Empty string is the minimum.
            if !s.is_empty() {
                out.push(Value::String(String::new()));
                // Halve the string.
                if s.len() > 1 {
                    let mid = s.len() / 2;
                    // Snap to char boundary so we don't slice
                    // mid-codepoint and panic.
                    let safe = (0..=mid)
                        .rev()
                        .find(|i| s.is_char_boundary(*i))
                        .unwrap_or(0);
                    out.push(Value::String(s[..safe].to_string()));
                }
            }
        }
        Value::Number(n) => {
            if n.as_f64() != Some(0.0) {
                out.push(Value::Number(serde_json::Number::from(0)));
            }
        }
        Value::Bool(b) => {
            if *b {
                out.push(Value::Bool(false));
            }
        }
        Value::Null => {}
    }
}

fn canonical_bytes(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

/// Convenience: build a `Map` from a `serde_json::Map`. Uses
/// `shift_remove` so the iteration order of the *remaining*
/// entries stays stable across passes — important for the
/// shrinker's determinism.
trait MapShiftRemove {
    fn shift_remove(&mut self, key: &str);
}

impl MapShiftRemove for Map<String, Value> {
    fn shift_remove(&mut self, key: &str) {
        // serde_json::Map::shift_remove preserves order of the
        // remaining entries when the `preserve_order` feature is
        // active. With the default feature it falls back to
        // BTreeMap which is already deterministic.
        self.remove(key);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shrink_drops_unrelated_keys() {
        let original = json!({
            "trigger": "boom",
            "noise1": "ignored",
            "noise2": [1, 2, 3, 4, 5],
            "noise3": {"deep": {"deeper": "still"}}
        });
        let result = shrink(&original, |v| {
            v.get("trigger").and_then(Value::as_str) == Some("boom")
        });
        // After shrinking we keep the `trigger` key with its
        // original value, drop everything else.
        assert_eq!(result.minimised.get("trigger"), Some(&json!("boom")));
        let obj = result.minimised.as_object().expect("obj");
        assert_eq!(obj.len(), 1, "minimised must have only the trigger key");
        assert!(result.byte_size.1 < result.byte_size.0);
    }

    #[test]
    fn shrink_empties_unconstrained_strings() {
        let original = json!({"path": "a/b/c/very/deep/nested/file.txt"});
        let result = shrink(&original, |v| v.get("path").is_some());
        // The predicate only requires `path` to *exist* — the
        // shrinker should drop its contents to empty.
        assert_eq!(result.minimised.get("path"), Some(&json!("")));
    }

    #[test]
    fn shrink_drops_array_elements() {
        let original = json!({"items": [1, 2, 3, 4, 5, 6, 7, 8]});
        let result = shrink(&original, |v| {
            v.get("items")
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.contains(&json!(7)))
        });
        // The predicate requires `7` to be present. Shrinker
        // should drop every other element.
        let arr = result
            .minimised
            .get("items")
            .and_then(Value::as_array)
            .expect("array");
        assert_eq!(arr, &vec![json!(7)]);
    }

    #[test]
    fn shrink_terminates_on_fixed_point() {
        let original = json!({"a": 1});
        // Predicate matches everything — shrinker should stop
        // when no further reduction reproduces.
        let result = shrink(&original, |_| true);
        // The minimum that still satisfies "anything" is the
        // empty object (drop the only key).
        assert_eq!(result.minimised, json!({}));
    }

    #[test]
    fn shrink_respects_step_cap() {
        // Predicate is unsatisfiable, so the shrinker keeps
        // trying every transformation. Verify we don't run
        // away.
        let original = json!({"a": 1, "b": "hello", "c": [1, 2, 3]});
        let mut count = 0;
        let result = shrink(&original, |_| {
            count += 1;
            false // never satisfied
        });
        assert!(
            result.steps <= MAX_STEPS,
            "should respect MAX_STEPS cap; got {}",
            result.steps
        );
        // Also: when the predicate never matches, we keep the
        // original.
        assert_eq!(result.minimised, original);
    }

    #[test]
    fn shrink_handles_unicode_strings_safely() {
        // Non-ASCII string with multibyte chars — shrinker must
        // not slice on a non-char boundary (would panic).
        let original = json!({"emoji": "🤖🌟⭐"});
        let result = shrink(&original, |v| v.get("emoji").is_some());
        // Should reach empty without panicking.
        assert_eq!(result.minimised.get("emoji"), Some(&json!("")));
    }

    #[test]
    fn shrink_preserves_structurally_required_keys() {
        let original = json!({"id": "abc", "extra": "noise", "more": "noise2"});
        let result = shrink(&original, |v| {
            v.get("id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        });
        // `id` must stay non-empty; `extra` and `more` go.
        let obj = result.minimised.as_object().expect("obj");
        assert!(obj.contains_key("id"), "id must remain");
        assert!(!obj.contains_key("extra"), "extra must go");
        assert!(!obj.contains_key("more"), "more must go");
    }
}
