use rand::Rng;
use serde_json::{json, Map, Number, Value};
use tracing::warn;

use super::strategies;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenMode {
    Conform,
    Adversarial,
    Mixed,
}

pub fn generate_payload(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    match generate_value(schema, rng, mode) {
        Value::Object(map) => Value::Object(map),
        _ => Value::Object(Map::new()),
    }
}

pub fn generate_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if contains_unsupported_keyword(schema) {
        warn!("schema contains unsupported composition keyword; falling back");
        return fallback_for(schema);
    }

    if let Some(value) = schema.get("const") {
        return value.clone();
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if values.is_empty() {
            return Value::Null;
        }
        return strategies::pick(rng, values).clone();
    }

    let effective_mode = match mode {
        GenMode::Mixed if strategies::chance(rng, 1, 5) => GenMode::Adversarial,
        GenMode::Mixed => GenMode::Conform,
        other => other,
    };

    let schema_type = schema_type(schema);
    match schema_type.as_deref() {
        Some("string") => string_value(schema, rng, effective_mode),
        Some("integer") => integer_value(schema, rng, effective_mode),
        Some("number") => number_value(schema, rng, effective_mode),
        Some("boolean") => Value::Bool(rng.next_u64() % 2 == 0),
        Some("array") => array_value(schema, rng, effective_mode),
        Some("object") | None => object_value(schema, rng, effective_mode),
        Some("null") => Value::Null,
        Some(other) => {
            warn!(
                schema_type = other,
                "unsupported schema type; returning null"
            );
            Value::Null
        }
    }
}

fn string_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return Value::String(strategies::long_or_tricky_string(rng));
    }

    let min = number_keyword(schema, "minLength").unwrap_or(0).max(0) as usize;
    let max = number_keyword(schema, "maxLength")
        .unwrap_or(32)
        .max(min as i64) as usize;
    let max = max.min(256);
    let span = max.saturating_sub(min) + 1;
    let len = min + ((rng.next_u64() as usize) % span);
    let value = (0..len)
        .map(|_| {
            let offset = (rng.next_u64() % 26) as u8;
            char::from(b'a' + offset)
        })
        .collect::<String>();
    Value::String(value)
}

fn integer_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return json!(strategies::boundary_int(rng));
    }

    let mut min = number_keyword(schema, "minimum").unwrap_or(-1000);
    let mut max = number_keyword(schema, "maximum").unwrap_or(1000);
    if number_keyword(schema, "exclusiveMinimum").is_some() {
        min = min.saturating_add(1);
    }
    if number_keyword(schema, "exclusiveMaximum").is_some() {
        max = max.saturating_sub(1);
    }
    if min > max {
        return json!(min);
    }

    let span = (max as i128 - min as i128 + 1).max(1) as u64;
    let mut value = min.saturating_add((rng.next_u64() % span) as i64);
    if let Some(multiple_of) = number_keyword(schema, "multipleOf").filter(|value| *value != 0) {
        value -= value.rem_euclid(multiple_of);
    }
    json!(value)
}

fn number_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial {
        return Number::from_f64(strategies::boundary_float(rng))
            .map(Value::Number)
            .unwrap_or(Value::Null);
    }

    let min = schema
        .get("minimum")
        .and_then(Value::as_f64)
        .unwrap_or(-1000.0);
    let max = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .unwrap_or(1000.0)
        .max(min);
    let unit = (rng.next_u64() as f64) / (u64::MAX as f64);
    let value = min + ((max - min) * unit);
    Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn array_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    if mode == GenMode::Adversarial && strategies::chance(rng, 1, 10) {
        return strategies::deep_nesting(1000);
    }

    let item_schema = schema.get("items").unwrap_or(&Value::Null);
    let min = number_keyword(schema, "minItems").unwrap_or(0).max(0) as usize;
    let default_max = if mode == GenMode::Adversarial { 128 } else { 8 };
    let max = number_keyword(schema, "maxItems")
        .unwrap_or(default_max)
        .max(min as i64) as usize;
    let max = max.min(default_max as usize);
    let span = max.saturating_sub(min) + 1;
    let len = min + ((rng.next_u64() as usize) % span);
    Value::Array(
        (0..len)
            .map(|_| generate_value(item_schema, rng, mode))
            .collect(),
    )
}

fn object_value(schema: &Value, rng: &mut impl Rng, mode: GenMode) -> Value {
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| properties.keys().cloned().collect());

    let mut object = Map::new();
    for (key, property_schema) in &properties {
        if mode == GenMode::Adversarial && required.contains(key) && strategies::chance(rng, 1, 20)
        {
            continue;
        }

        let value = if mode == GenMode::Adversarial && strategies::chance(rng, 1, 20) {
            strategies::wrong_type_for(schema_type(property_schema).as_deref().unwrap_or("null"))
        } else {
            generate_value(property_schema, rng, mode)
        };
        object.insert(key.clone(), value);
    }

    if mode == GenMode::Adversarial
        && schema
            .get("additionalProperties")
            .and_then(Value::as_bool)
            .is_some_and(|allowed| !allowed)
        && strategies::chance(rng, 1, 5)
    {
        object.insert("unexpected_extra".to_string(), json!("extra"));
    }

    Value::Object(object)
}

fn schema_type(schema: &Value) -> Option<String> {
    match schema.get("type") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .map(ToOwned::to_owned),
        _ => {
            if schema.get("properties").is_some() {
                Some("object".to_string())
            } else {
                None
            }
        }
    }
}

fn number_keyword(schema: &Value, key: &str) -> Option<i64> {
    schema.get(key).and_then(Value::as_i64)
}

fn contains_unsupported_keyword(schema: &Value) -> bool {
    const UNSUPPORTED: &[&str] = &[
        "$ref",
        "$defs",
        "oneOf",
        "anyOf",
        "allOf",
        "if",
        "then",
        "else",
        "not",
        "dependentRequired",
    ];

    schema
        .as_object()
        .is_some_and(|object| UNSUPPORTED.iter().any(|key| object.contains_key(*key)))
}

fn fallback_for(schema: &Value) -> Value {
    match schema_type(schema).as_deref() {
        Some("object") => Value::Object(Map::new()),
        _ => Value::Null,
    }
}
