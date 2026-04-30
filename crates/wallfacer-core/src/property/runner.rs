use rand::RngCore;
use regex::Regex;
use serde_json::{json, Map, Number, Value};
use thiserror::Error;

use super::{
    dsl::{Assertion, Invariant, JsonType, ValueKind, ValueSpec},
    jsonpath,
};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("{0}")]
    Assertion(String),
    #[error(transparent)]
    JsonPath(#[from] jsonpath::JsonPathError),
    #[error("invalid regex `{pattern}`: {source}")]
    Regex {
        pattern: String,
        source: regex::Error,
    },
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

pub fn evaluate(invariant: &Invariant, input: Value, response: Value) -> Result<()> {
    let context = json!({
        "input": input,
        "response": response,
    });

    for assertion in &invariant.assertions {
        evaluate_assertion(assertion, &context)?;
    }

    Ok(())
}

fn evaluate_assertion(assertion: &Assertion, context: &Value) -> Result<()> {
    match assertion {
        Assertion::Equals { lhs, rhs } => {
            let left = operand(lhs, context)?;
            let right = operand(rhs, context)?;
            if left == right {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {left} to equal {right}"
                )))
            }
        }
        Assertion::NotEquals { lhs, rhs } => {
            let left = operand(lhs, context)?;
            let right = operand(rhs, context)?;
            if left != right {
                Ok(())
            } else {
                Err(RunnerError::Assertion(format!(
                    "expected {left} to differ from {right}"
                )))
            }
        }
        Assertion::AtMost { path, value } => compare_number(path, value, context, |a, b| a <= b),
        Assertion::AtLeast { path, value } => compare_number(path, value, context, |a, b| a >= b),
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
    }
}

fn operand(value: &Value, context: &Value) -> Result<Value> {
    match value {
        Value::String(path) if path.starts_with('$') => Ok(jsonpath::resolve_one(context, path)?),
        literal => Ok(literal.clone()),
    }
}

fn compare_number(
    path: &str,
    value: &Value,
    context: &Value,
    compare: impl FnOnce(f64, f64) -> bool,
) -> Result<()> {
    let left = jsonpath::resolve_one(context, path)?;
    let right = operand(value, context)?;
    let Some(left) = left.as_f64() else {
        return Err(RunnerError::Assertion(format!(
            "expected {path} to resolve to a number"
        )));
    };
    let Some(right) = right.as_f64() else {
        return Err(RunnerError::Assertion(
            "expected comparison value to be a number".to_string(),
        ));
    };

    if compare(left, right) {
        Ok(())
    } else {
        Err(RunnerError::Assertion(format!(
            "numeric comparison failed: {left} vs {right}"
        )))
    }
}

fn compare_length(
    path: &str,
    value: &Value,
    context: &Value,
    compare: impl FnOnce(usize, usize) -> bool,
) -> Result<()> {
    let left = jsonpath::resolve_one(context, path)?;
    let right = operand(value, context)?;
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
