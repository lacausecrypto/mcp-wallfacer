use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
};

use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::corpus::sanitize_tool_name;

#[derive(Debug, Error)]
pub enum DifferentialError {
    #[error("failed to create schema directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to write schema {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to read schema {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to parse schema {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, DifferentialError>;

pub fn inferred_schema_dir() -> PathBuf {
    PathBuf::from(".wallfacer/inferred_schemas")
}

pub fn schema_path(dir: &Path, tool_name: &str) -> PathBuf {
    dir.join(format!("{}.json", sanitize_tool_name(tool_name)))
}

pub fn save_schema(dir: &Path, tool_name: &str, schema: &Value) -> Result<PathBuf> {
    fs::create_dir_all(dir).map_err(|source| DifferentialError::CreateDir {
        path: dir.to_path_buf(),
        source,
    })?;

    let path = schema_path(dir, tool_name);
    // `serde_json::to_string_pretty` on a `Value` is infallible.
    let body = serde_json::to_string_pretty(schema).unwrap_or_else(|_| "{}".to_string());
    fs::write(&path, body).map_err(|source| DifferentialError::Write {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

pub fn load_schema(dir: &Path, tool_name: &str) -> Result<Option<Value>> {
    let path = schema_path(dir, tool_name);
    if !path.is_file() {
        return Ok(None);
    }

    let body = fs::read_to_string(&path).map_err(|source| DifferentialError::Read {
        path: path.clone(),
        source,
    })?;
    let schema = serde_json::from_str(&body).map_err(|source| DifferentialError::Parse {
        path: path.clone(),
        source,
    })?;
    Ok(Some(schema))
}

pub fn response_value(result: &rmcp::model::CallToolResult) -> Value {
    result.structured_content.clone().unwrap_or_else(|| {
        // `CallToolResult` is fully `Serialize`; fall back to `Null` if a future
        // SDK revision introduces an un-serializable field rather than panicking.
        serde_json::to_value(result).unwrap_or(Value::Null)
    })
}

pub fn boundary_payload(schema: &Value) -> Value {
    match boundary_value(schema) {
        Value::Object(map) => Value::Object(map),
        _ => Value::Object(Map::new()),
    }
}

pub fn infer_schema(values: &[Value]) -> Value {
    if values.is_empty() {
        return json!({});
    }
    infer_values(values)
}

fn infer_values(values: &[Value]) -> Value {
    if values.iter().all(Value::is_null) {
        return json!({"type": "null"});
    }

    let mut types = values.iter().map(type_name).collect::<BTreeSet<_>>();
    if types.len() > 1 {
        let type_values = types.into_iter().map(Value::String).collect::<Vec<_>>();
        return json!({ "type": type_values });
    }

    match types.pop_first().as_deref() {
        Some("object") => infer_object(values),
        Some("array") => infer_array(values),
        Some("integer") => json!({"type": "integer"}),
        Some("number") => json!({"type": "number"}),
        Some("string") => json!({"type": "string"}),
        Some("boolean") => json!({"type": "boolean"}),
        Some("null") => json!({"type": "null"}),
        _ => json!({}),
    }
}

fn infer_object(values: &[Value]) -> Value {
    let objects = values
        .iter()
        .filter_map(Value::as_object)
        .collect::<Vec<_>>();
    let mut property_values = BTreeMap::<String, Vec<Value>>::new();
    let mut required = BTreeSet::<String>::new();

    if let Some(first) = objects.first() {
        required.extend(first.keys().cloned());
    }

    for object in &objects {
        let keys = object.keys().cloned().collect::<BTreeSet<_>>();
        required = required.intersection(&keys).cloned().collect();

        for (key, value) in *object {
            property_values
                .entry(key.clone())
                .or_default()
                .push(value.clone());
        }
    }

    let mut properties = Map::new();
    for (key, values) in property_values {
        properties.insert(key, infer_values(&values));
    }

    json!({
        "type": "object",
        "properties": properties,
        "required": required.into_iter().collect::<Vec<_>>(),
        "additionalProperties": true
    })
}

fn infer_array(values: &[Value]) -> Value {
    let items = values
        .iter()
        .filter_map(Value::as_array)
        .flat_map(|items| items.iter().cloned())
        .collect::<Vec<_>>();

    json!({
        "type": "array",
        "items": infer_schema(&items)
    })
}

fn boundary_value(schema: &Value) -> Value {
    if let Some(value) = schema.get("const") {
        return value.clone();
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values.first().cloned().unwrap_or(Value::Null);
    }

    match schema_type(schema).as_deref() {
        Some("object") | None => {
            let mut object = Map::new();
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let required = schema
                .get("required")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| properties.keys().cloned().collect());

            for key in required {
                if let Some(property_schema) = properties.get(&key) {
                    object.insert(key, boundary_value(property_schema));
                }
            }
            Value::Object(object)
        }
        Some("integer") => {
            if let Some(max) = schema.get("maximum").and_then(Value::as_i64) {
                json!(max)
            } else if let Some(min) = schema.get("minimum").and_then(Value::as_i64) {
                json!(min)
            } else {
                json!(1)
            }
        }
        Some("number") => {
            if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
                json!(max)
            } else if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
                json!(min)
            } else {
                json!(1.0)
            }
        }
        Some("string") => Value::String("wallfacer".to_string()),
        Some("boolean") => Value::Bool(true),
        Some("array") => Value::Array(Vec::new()),
        Some("null") => Value::Null,
        Some(_) => Value::Null,
    }
}

fn schema_type(schema: &Value) -> Option<String> {
    match schema.get("type") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .map(ToOwned::to_owned),
        _ if schema.get("properties").is_some() => Some("object".to_string()),
        _ => None,
    }
}

fn type_name(value: &Value) -> String {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
    .to_string()
}
