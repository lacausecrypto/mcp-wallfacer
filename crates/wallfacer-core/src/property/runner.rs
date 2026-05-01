//! Property invariant evaluator.
//!
//! Phase D rewrites the runner to:
//!
//! * use [`Operand::resolve`] instead of the legacy `starts_with('$')`
//!   heuristic, while preserving full v1 backwards compatibility;
//! * support boolean combinators (`all_of`, `any_of`, `not`),
//!   element-wise iteration (`for_each`), and inline schema validation
//!   (`matches_schema`);
//! * forbid `unwrap` / `expect` at the module level so any future
//!   regression is caught by the workspace clippy gate.

#![deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use jsonschema::validator_for;
use rand::RngCore;
use regex::Regex;
use serde_json::{json, Map, Number, Value};
use thiserror::Error;
use tracing::warn;

use super::{
    dsl::{
        Assertion, FixtureExpect, Invariant, JsonType, Operand, TestFixture, ValueKind, ValueSpec,
    },
    jsonpath,
};

/// Errors raised while evaluating a single invariant case.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// An assertion produced a human-readable failure.
    #[error("{0}")]
    Assertion(String),
    /// A JSONPath used by the assertion did not resolve cleanly.
    #[error(transparent)]
    JsonPath(#[from] jsonpath::JsonPathError),
    /// A regex inside a `matches_regex` assertion failed to compile.
    #[error("invalid regex `{pattern}`: {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    /// A JSON Schema inside a `matches_schema` assertion failed to compile.
    #[error("invalid inline schema in `matches_schema`: {0}")]
    Schema(String),
}

pub type Result<T> = std::result::Result<T, RunnerError>;

pub fn input_for_case(invariant: &Invariant, case_index: u32, rng: &mut impl RngCore) -> Value {
    if let Some(fixed) = &invariant.fixed {
        return Value::Object(
            fixed
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
    }

    let mut input = Map::new();
    if let Some(generate) = &invariant.generate {
        for (key, spec) in generate {
            let value = if case_index == 0 {
                boundary_value(spec)
            } else {
                generated_value(spec, rng)
            };
            input.insert(key.clone(), value);
        }
    }
    Value::Object(input)
}

/// Top-level entry point: evaluates every assertion of an invariant against
/// a freshly built `{input, response}` context.
pub fn evaluate(invariant: &Invariant, input: Value, response: Value) -> Result<()> {
    evaluate_step_assertions(&invariant.assertions, input, response)
}

/// Evaluates a free-form list of assertions against a fresh
/// `{input, response}` context. Used by the sequence runner where
/// the assertions live on a [`super::dsl::SequenceStep`] rather than
/// an [`Invariant`]. Behaviour is otherwise identical to
/// [`evaluate`].
pub fn evaluate_step_assertions(
    assertions: &[Assertion],
    input: Value,
    response: Value,
) -> Result<()> {
    let context = json!({
        "input": input,
        "response": response,
    });
    for assertion in assertions {
        evaluate_assertion(assertion, &context)?;
    }
    Ok(())
}

/// Outcome of [`evaluate_fixture`]: the comparison between what the
/// fixture asked for and what the runner actually produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureOutcome {
    /// Observed matches `expected`; this fixture passed.
    Match,
    /// Observed differs from `expected`; this fixture failed.
    Mismatch {
        /// What the fixture said should happen.
        expected: FixtureExpect,
        /// What the runner actually observed.
        observed: FixtureExpect,
        /// Human-readable detail (assertion message when the runner
        /// returned `Err`, empty string on `Ok`).
        detail: String,
    },
    /// The runner returned a structural error (bad path, malformed
    /// regex / schema). The invariant itself is broken — this fixture
    /// can neither pass nor fail meaningfully.
    Structural {
        /// Pass-through of the structural error.
        error: String,
    },
}

/// Phase H — evaluates an invariant against a synthetic
/// `(input, response)` pair scripted by a [`TestFixture`] and reports
/// whether the observed outcome matches the fixture's `expect`.
pub fn evaluate_fixture(invariant: &Invariant, fixture: &TestFixture) -> FixtureOutcome {
    let input = fixture.input.clone().unwrap_or_else(|| {
        let map = invariant
            .fixed
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect::<serde_json::Map<_, _>>();
        Value::Object(map)
    });
    match evaluate(invariant, input, fixture.response.clone()) {
        Ok(()) => match fixture.expect {
            FixtureExpect::Pass => FixtureOutcome::Match,
            FixtureExpect::Fail => FixtureOutcome::Mismatch {
                expected: FixtureExpect::Fail,
                observed: FixtureExpect::Pass,
                detail: String::new(),
            },
        },
        Err(RunnerError::Assertion(message)) => match fixture.expect {
            FixtureExpect::Fail => FixtureOutcome::Match,
            FixtureExpect::Pass => FixtureOutcome::Mismatch {
                expected: FixtureExpect::Pass,
                observed: FixtureExpect::Fail,
                detail: message,
            },
        },
        Err(other) => FixtureOutcome::Structural {
            error: other.to_string(),
        },
    }
}

fn evaluate_assertion(assertion: &Assertion, context: &Value) -> Result<()> {
    match assertion {
        Assertion::Equals { lhs, rhs } => {
            let left = lhs.resolve(context)?;
            let right = rhs.resolve(context)?;
            if left == right {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {left} to equal {right}"
                )))
            }
        }
        Assertion::NotEquals { lhs, rhs } => {
            let left = lhs.resolve(context)?;
            let right = rhs.resolve(context)?;
            if left != right {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {left} to differ from {right}"
                )))
            }
        }
        Assertion::AtMost { path, value } => compare_number(path, value, context, |o| {
            matches!(o, std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        }),
        Assertion::AtLeast { path, value } => compare_number(path, value, context, |o| {
            matches!(o, std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        }),
        Assertion::LengthEq { path, value } => compare_length(path, value, context, |a, b| a == b),
        Assertion::LengthAtMost { path, value } => {
            compare_length(path, value, context, |a, b| a <= b)
        }
        Assertion::LengthAtLeast { path, value } => {
            compare_length(path, value, context, |a, b| a >= b)
        }
        Assertion::IsType { path, expected } => {
            let value = jsonpath::resolve_one(context, path)?;
            let actual = json_type(&value);
            if actual == *expected {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {path} to be {expected:?}, got {actual:?}"
                )))
            }
        }
        Assertion::MatchesRegex { path, pattern } => {
            let value = jsonpath::resolve_one(context, path)?;
            let Some(text) = value.as_str() else {
                return Err(RunnerError::Assertion(format!(
                    "expected {path} to resolve to a string"
                )));
            };
            let regex = Regex::new(pattern).map_err(|source| RunnerError::Regex {
                pattern: pattern.clone(),
                source,
            })?;
            if regex.is_match(text) {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {path} to match {pattern}"
                )))
            }
        }
        Assertion::AllOf { assertions } => {
            for child in assertions {
                evaluate_assertion(child, context)?;
            }
            Ok(())
        }
        Assertion::AnyOf { assertions } => evaluate_any_of(assertions, context),
        Assertion::Not { assertion } => match evaluate_assertion(assertion, context) {
            Ok(()) => Err(RunnerError::Assertion(
                "expected child assertion to fail under `not`".to_string(),
            )),
            // A failing child *is* OK semantically when:
            //  - it produced an `Assertion` failure;
            //  - it referenced a path that did not resolve. Missing
            //    paths are equivalent to "child assertion does not
            //    hold" rather than a malformed invariant — promoting
            //    them to hard errors would make `not(matches_regex
            //    path=...)` surprising whenever the path is absent.
            // Other errors (regex compile, schema compile, malformed
            // YAML) are genuinely structural and propagate.
            Err(RunnerError::Assertion(_)) => Ok(()),
            Err(RunnerError::JsonPath(jsonpath::JsonPathError::Missing(_))) => Ok(()),
            Err(other) => Err(other),
        },
        Assertion::ForEach { path, assertions } => evaluate_for_each(path, assertions, context),
        Assertion::MatchesSchema { path, schema } => {
            let target = jsonpath::resolve_one(context, path)?;
            let validator =
                validator_for(schema).map_err(|err| RunnerError::Schema(err.to_string()))?;
            if validator.is_valid(&target) {
                Ok(())
            } else {
                let errors = validator
                    .iter_errors(&target)
                    .map(|err| format!("{err} at {}", err.instance_path()))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(RunnerError::Assertion(format!(
                    "value at {path} does not validate against inline schema: {errors}"
                )))
            }
        }
    }
}

fn evaluate_any_of(assertions: &[Assertion], context: &Value) -> Result<()> {
    if assertions.is_empty() {
        return Err(RunnerError::Assertion(
            "`any_of` requires at least one child assertion".to_string(),
        ));
    }
    let mut last_assertion_error: Option<String> = None;
    for child in assertions {
        match evaluate_assertion(child, context) {
            Ok(()) => return Ok(()),
            Err(RunnerError::Assertion(message)) => {
                last_assertion_error = Some(message);
            }
            // A missing path inside one branch of `any_of` simply means
            // "this branch does not apply" — try the next one. Other
            // structural errors (regex compile, schema compile) signal
            // a broken invariant and propagate.
            Err(RunnerError::JsonPath(jsonpath::JsonPathError::Missing(path))) => {
                last_assertion_error = Some(format!("path `{path}` did not resolve"));
            }
            Err(other) => return Err(other),
        }
    }
    Err(RunnerError::Assertion(format!(
        "no `any_of` branch matched (last failure: {})",
        last_assertion_error.unwrap_or_else(|| "unknown".to_string())
    )))
}

fn evaluate_for_each(path: &str, assertions: &[Assertion], context: &Value) -> Result<()> {
    let nodes = jsonpath::resolve(context, path)?;
    if nodes.is_empty() {
        // `for_each` over an empty set is vacuously true. Emit a warning
        // so an author who fat-fingered a JSONPath does not ship an
        // invariant that silently always passes. Run `wallfacer property
        // -v` to see this.
        warn!(
            jsonpath = path,
            "for_each path matched zero nodes; the assertion is vacuously true. \
             Double-check the path or wrap intentional empty-set cases in `any_of` / `not`."
        );
        return Ok(());
    }
    for (index, node) in nodes.into_iter().enumerate() {
        // Build a child context with the iterated node exposed under
        // `$.item`. Original `$.input` / `$.response` remain accessible so
        // assertions can correlate the current element with global state.
        let Some(base) = context.as_object() else {
            return Err(RunnerError::Assertion(
                "internal: evaluation context must be an object".to_string(),
            ));
        };
        let mut child = base.clone();
        child.insert("item".to_string(), node);
        child.insert("index".to_string(), json!(index));
        let child_context = Value::Object(child);
        for assertion in assertions {
            evaluate_assertion(assertion, &child_context).map_err(|err| match err {
                RunnerError::Assertion(message) => {
                    RunnerError::Assertion(format!("for_each at {path}[{index}]: {message}"))
                }
                other => other,
            })?;
        }
    }
    Ok(())
}

fn compare_number(
    path: &str,
    value: &Operand,
    context: &Value,
    compare: impl Fn(std::cmp::Ordering) -> bool,
) -> Result<()> {
    let left = jsonpath::resolve_one(context, path)?;
    let right = value.resolve(context)?;

    // Fast path: when both operands fit in `i128` (covers any JSON
    // integer, signed or unsigned), compare without going through f64.
    // f64 only has 53 bits of mantissa, so values like
    // `9_007_199_254_740_993` lose precision and equal their
    // `…992` neighbour — silently corrupting `at_most`/`at_least`.
    if let (Some(l), Some(r)) = (as_i128(&left), as_i128(&right)) {
        if compare(l.cmp(&r)) {
            return Ok(());
        }
        return Err(RunnerError::Assertion(format!(
            "numeric comparison failed: {l} vs {r}"
        )));
    }

    let Some(left_f) = left.as_f64() else {
        return Err(RunnerError::Assertion(format!(
            "expected {path} to resolve to a number"
        )));
    };
    let Some(right_f) = right.as_f64() else {
        return Err(RunnerError::Assertion(
            "expected comparison value to be a number".to_string(),
        ));
    };
    let ordering = left_f
        .partial_cmp(&right_f)
        .ok_or_else(|| RunnerError::Assertion("comparison against NaN".to_string()))?;
    if compare(ordering) {
        Ok(())
    } else {
        Err(RunnerError::Assertion(format!(
            "numeric comparison failed: {left_f} vs {right_f}"
        )))
    }
}

fn as_i128(value: &Value) -> Option<i128> {
    let Value::Number(n) = value else {
        return None;
    };
    if let Some(i) = n.as_i64() {
        Some(i as i128)
    } else {
        n.as_u64().map(|u| u as i128)
    }
}

fn compare_length(
    path: &str,
    value: &Operand,
    context: &Value,
    compare: impl FnOnce(usize, usize) -> bool,
) -> Result<()> {
    let left = jsonpath::resolve_one(context, path)?;
    let right = value.resolve(context)?;
    let Some(right) = right.as_u64().map(|value| value as usize) else {
        return Err(RunnerError::Assertion(
            "expected comparison value to be an integer".to_string(),
        ));
    };
    let Some(left) = length(&left) else {
        return Err(RunnerError::Assertion(format!(
            "expected {path} to resolve to an array or string"
        )));
    };
    if compare(left, right) {
        Ok(())
    } else {
        Err(RunnerError::Assertion(format!(
            "length comparison failed: {left} vs {right}"
        )))
    }
}

fn length(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::String(text) => Some(text.chars().count()),
        _ => None,
    }
}

fn json_type(value: &Value) -> JsonType {
    match value {
        Value::Null => JsonType::Null,
        Value::Bool(_) => JsonType::Boolean,
        Value::Number(number) if number.is_i64() || number.is_u64() => JsonType::Integer,
        Value::Number(_) => JsonType::Number,
        Value::String(_) => JsonType::String,
        Value::Array(_) => JsonType::Array,
        Value::Object(_) => JsonType::Object,
    }
}

impl Operand {
    /// Resolves an operand against the `{input, response}` context.
    ///
    /// * [`Operand::Path`] → JSONPath lookup (errors if missing).
    /// * [`Operand::Literal`] → returned verbatim.
    /// * [`Operand::Direct`] strings starting with `$` → JSONPath lookup
    ///   (legacy v1 contract); anything else → returned verbatim.
    pub fn resolve(&self, context: &Value) -> Result<Value> {
        match self {
            Operand::Path { path } => Ok(jsonpath::resolve_one(context, path)?),
            Operand::Literal { value } => Ok(value.clone()),
            Operand::Direct(Value::String(s)) if s.starts_with('$') => {
                Ok(jsonpath::resolve_one(context, s)?)
            }
            Operand::Direct(value) => Ok(value.clone()),
        }
    }
}

fn boundary_value(spec: &ValueSpec) -> Value {
    match spec.kind {
        ValueKind::String => {
            let len = spec.max_length.or(spec.min_length).unwrap_or(8).min(1024);
            Value::String("x".repeat(len))
        }
        ValueKind::Integer => json!(spec.max.or(spec.min).unwrap_or(1)),
        ValueKind::Number => Number::from_f64(spec.max.or(spec.min).unwrap_or(1) as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        ValueKind::Boolean => Value::Bool(true),
        ValueKind::Array => {
            let len = spec.max_items.or(spec.min_items).unwrap_or(1).min(64);
            let item_spec = spec.items.as_deref();
            Value::Array(
                (0..len)
                    .map(|_| item_spec.map(boundary_value).unwrap_or(Value::Null))
                    .collect(),
            )
        }
    }
}

fn generated_value(spec: &ValueSpec, rng: &mut impl RngCore) -> Value {
    match spec.kind {
        ValueKind::String => {
            let min = spec.min_length.unwrap_or(0);
            let max = spec.max_length.unwrap_or(32).max(min).min(1024);
            let len = min + (rng.next_u64() as usize % (max - min + 1));
            Value::String("a".repeat(len))
        }
        ValueKind::Integer => {
            let min = spec.min.unwrap_or(-100);
            let max = spec.max.unwrap_or(100).max(min);
            let span = (max as i128 - min as i128 + 1) as u64;
            json!(min + (rng.next_u64() % span) as i64)
        }
        ValueKind::Number => {
            let min = spec.min.unwrap_or(-100) as f64;
            let max = (spec.max.unwrap_or(100) as f64).max(min);
            let unit = rng.next_u64() as f64 / u64::MAX as f64;
            Number::from_f64(min + (max - min) * unit)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        ValueKind::Boolean => Value::Bool((rng.next_u64() & 1) == 0),
        ValueKind::Array => {
            let min = spec.min_items.unwrap_or(0);
            let max = spec.max_items.unwrap_or(8).max(min).min(64);
            let len = min + (rng.next_u64() as usize % (max - min + 1));
            let item_spec = spec.items.as_deref();
            Value::Array(
                (0..len)
                    .map(|_| {
                        item_spec
                            .map(|item| generated_value(item, rng))
                            .unwrap_or(Value::Null)
                    })
                    .collect(),
            )
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unwrap_in_result
)]
mod tests {
    use super::*;
    use crate::property::dsl::parse;

    fn evaluate_yaml(source: &str, input: Value, response: Value) -> Result<()> {
        let file = parse(source).unwrap();
        evaluate(&file.invariants[0], input, response)
    }

    #[test]
    fn explicit_path_operand_works() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: equals
        lhs: { path: "$.response.x" }
        rhs: { value: 42 }
"#;
        evaluate_yaml(source, json!({}), json!({"x": 42})).unwrap();
        assert!(evaluate_yaml(source, json!({}), json!({"x": 41})).is_err());
    }

    #[test]
    fn at_least_uses_integer_comparison_beyond_f64_mantissa() {
        // 9_007_199_254_740_993 == 2^53 + 1, the first integer that loses
        // precision when round-tripped through f64. With the previous
        // f64-only path, `>= 9007199254740993` accepted 9007199254740992,
        // which is silently wrong.
        let source = r#"
version: 2
invariants:
  - name: precision
    tool: x
    fixed: {}
    assert:
      - kind: at_least
        path: "$.response.n"
        value: { value: 9007199254740993 }
"#;
        // Equal: must pass.
        evaluate_yaml(source, json!({}), json!({"n": 9_007_199_254_740_993_i64})).unwrap();
        // One below: must fail (used to silently pass via f64 rounding).
        let err =
            evaluate_yaml(source, json!({}), json!({"n": 9_007_199_254_740_992_i64})).unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(_)));
    }

    #[test]
    fn legacy_string_operand_still_works() {
        let source = r#"
version: 1
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: equals
        lhs: "$.response.x"
        rhs: "$.input.expected"
"#;
        evaluate_yaml(source, json!({"expected": 7}), json!({"x": 7})).unwrap();
    }

    #[test]
    fn all_of_combines_assertions() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: all_of
        assert:
          - kind: equals
            lhs: { path: "$.response.a" }
            rhs: { value: 1 }
          - kind: at_most
            path: "$.response.b"
            value: { value: 5 }
"#;
        evaluate_yaml(source, json!({}), json!({"a": 1, "b": 4})).unwrap();
        let err = evaluate_yaml(source, json!({}), json!({"a": 1, "b": 99})).unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(_)));
    }

    #[test]
    fn any_of_succeeds_when_one_branch_passes() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: any_of
        assert:
          - kind: equals
            lhs: { path: "$.response.a" }
            rhs: { value: 1 }
          - kind: equals
            lhs: { path: "$.response.a" }
            rhs: { value: 2 }
"#;
        evaluate_yaml(source, json!({}), json!({"a": 2})).unwrap();
        let err = evaluate_yaml(source, json!({}), json!({"a": 9})).unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(message) if message.contains("any_of")));
    }

    #[test]
    fn not_inverts_assertion_outcome() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: not
        assertion:
          kind: equals
          lhs: { path: "$.response.a" }
          rhs: { value: 0 }
"#;
        evaluate_yaml(source, json!({}), json!({"a": 5})).unwrap();
        let err = evaluate_yaml(source, json!({}), json!({"a": 0})).unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(_)));
    }

    #[test]
    fn for_each_visits_every_node() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: for_each
        path: "$.response.items[*]"
        assert:
          - kind: at_least
            path: "$.item.score"
            value: { value: 0 }
"#;
        evaluate_yaml(
            source,
            json!({}),
            json!({"items": [{"score": 1}, {"score": 5}]}),
        )
        .unwrap();
        let err = evaluate_yaml(
            source,
            json!({}),
            json!({"items": [{"score": 1}, {"score": -3}]}),
        )
        .unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(message) if message.contains("for_each at")));
    }

    #[test]
    fn matches_schema_validates_inline_schema() {
        let source = r#"
version: 2
invariants:
  - name: t
    tool: x
    fixed: {}
    assert:
      - kind: matches_schema
        path: "$.response.user"
        schema:
          type: object
          required: [name]
          properties:
            name: { type: string }
            age: { type: integer, minimum: 0 }
"#;
        evaluate_yaml(
            source,
            json!({}),
            json!({"user": {"name": "alice", "age": 30}}),
        )
        .unwrap();
        let err = evaluate_yaml(source, json!({}), json!({"user": {"age": -1}})).unwrap_err();
        assert!(matches!(err, RunnerError::Assertion(message) if message.contains("schema")));
    }
}
