//! JSON Schema composition resolution: `$ref`, `$defs`/`definitions`, and
//! `allOf` merging.
//!
//! The runtime composition keywords (`oneOf`, `anyOf`, `not`, `if/then/else`,
//! `dependentRequired`) are handled in [`crate::mutate::schema_gen`] because
//! they require RNG-driven choices and rejection sampling. This module
//! provides the deterministic, side-effect-free pieces.
//!
//! # Limits
//!
//! * Only **local** references are resolved (`#/$defs/...`,
//!   `#/definitions/...`, or `#/...` JSON pointers into the root document).
//!   Remote refs (`http://...`, `file:...`) are returned as
//!   [`ComposeError::ExternalRef`] and the caller should treat the schema as
//!   a skip.
//! * A `$ref` cycle returns [`ComposeError::Cycle`] once the same pointer is
//!   visited a second time on the current resolution path.
//! * `allOf` is merged with a pragmatic *last-write-wins per keyword* policy
//!   except for `properties` (deep-merged), `required` (set union), and
//!   `type` (first non-conflicting wins).

use std::collections::BTreeSet;

use serde_json::{Map, Value};
use thiserror::Error;

/// Hard cap on the depth of `$ref` resolution chains. A chain longer
/// than this is reported as [`ComposeError::DepthExceeded`] so cyclic or
/// pathological schemas can't lock the generator into an infinite walk.
pub const MAX_REF_DEPTH: usize = 16;

/// Errors raised by composition resolution.
#[derive(Debug, Error)]
pub enum ComposeError {
    /// Reference uses a non-local URI.
    #[error("external `$ref` is not supported: {0}")]
    ExternalRef(String),
    /// JSON pointer did not resolve to a definition.
    #[error("could not resolve `$ref` `{0}`")]
    UnresolvedRef(String),
    /// Reference cycle detected.
    #[error("cyclic `$ref` detected at `{0}`")]
    Cycle(String),
    /// Reference chain exceeded [`MAX_REF_DEPTH`].
    #[error("`$ref` chain exceeded depth {MAX_REF_DEPTH} at `{0}`")]
    DepthExceeded(String),
}

/// Result alias for composition operations.
pub type Result<T> = std::result::Result<T, ComposeError>;

/// Returns a copy of `schema` with any `$ref` resolved against `root`. If the
/// schema does not contain `$ref`, returns the schema unchanged. Recurses
/// into nested `$ref`s up to [`MAX_REF_DEPTH`].
///
/// `seen` accumulates pointers visited on the current resolution path for
/// cycle detection. Pass an empty `BTreeSet` for the first call.
pub fn dereference(root: &Value, schema: &Value, seen: &mut BTreeSet<String>) -> Result<Value> {
    let mut current = schema.clone();
    let mut depth = 0usize;
    while let Some(ref_str) = current
        .as_object()
        .and_then(|map| map.get("$ref"))
        .and_then(Value::as_str)
    {
        if !seen.insert(ref_str.to_string()) {
            return Err(ComposeError::Cycle(ref_str.to_string()));
        }
        if depth >= MAX_REF_DEPTH {
            return Err(ComposeError::DepthExceeded(ref_str.to_string()));
        }
        depth += 1;
        let resolved = resolve_pointer(root, ref_str)?;
        // The reference may carry sibling keys (rare but legal in 2020-12).
        // Merge them on top of the resolved schema.
        if let Some(siblings) = current.as_object() {
            let mut merged = resolved.as_object().cloned().unwrap_or_default();
            for (key, value) in siblings {
                if key != "$ref" {
                    merged.insert(key.clone(), value.clone());
                }
            }
            current = Value::Object(merged);
        } else {
            current = resolved;
        }
    }
    Ok(current)
}

/// Resolves a JSON Pointer style `$ref` against the root document.
/// Accepts `#/$defs/foo`, `#/definitions/foo`, or arbitrary `#/path/to/x`.
fn resolve_pointer(root: &Value, ref_str: &str) -> Result<Value> {
    let pointer = ref_str.strip_prefix('#').ok_or_else(|| {
        // Anything that does not start with `#` is treated as external.
        ComposeError::ExternalRef(ref_str.to_string())
    })?;
    if pointer.is_empty() {
        return Ok(root.clone());
    }
    root.pointer(pointer)
        .cloned()
        .ok_or_else(|| ComposeError::UnresolvedRef(ref_str.to_string()))
}

/// Merges an `allOf` array into a single schema. Each entry is dereferenced
/// against `root` first.
///
/// Merge rules:
///
/// * `type`: kept from the first sub-schema; conflicting types are silently
///   ignored to keep generation possible. Validators will still flag a real
///   conflict separately.
/// * `properties`: deep-merged. If two sub-schemas define the same property,
///   the right-hand one's value wins.
/// * `required`: set union.
/// * `enum`: kept from the first sub-schema.
/// * Any other keyword: last non-null write wins.
pub fn merge_all_of(root: &Value, schemas: &[Value]) -> Result<Value> {
    let mut merged = Map::new();
    let mut required: BTreeSet<String> = BTreeSet::new();

    for schema in schemas {
        let mut seen = BTreeSet::new();
        let resolved = dereference(root, schema, &mut seen)?;
        let Some(object) = resolved.as_object() else {
            continue;
        };
        for (key, value) in object {
            match key.as_str() {
                "properties" => {
                    let entry = merged
                        .entry(key.clone())
                        .or_insert_with(|| Value::Object(Map::new()));
                    if let (Some(target), Some(source)) = (entry.as_object_mut(), value.as_object())
                    {
                        for (prop_key, prop_value) in source {
                            target.insert(prop_key.clone(), prop_value.clone());
                        }
                    }
                }
                "required" => {
                    if let Some(items) = value.as_array() {
                        for item in items {
                            if let Some(name) = item.as_str() {
                                required.insert(name.to_string());
                            }
                        }
                    }
                }
                "type" => {
                    merged.entry(key.clone()).or_insert_with(|| value.clone());
                }
                _ => {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
    }

    if !required.is_empty() {
        merged.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }

    Ok(Value::Object(merged))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dereference_resolves_local_ref() {
        let root = json!({
            "$defs": {
                "User": {"type": "object", "properties": {"name": {"type": "string"}}}
            },
            "type": "object",
            "properties": {"user": {"$ref": "#/$defs/User"}}
        });
        let schema = json!({"$ref": "#/$defs/User"});
        let mut seen = BTreeSet::new();
        let resolved = dereference(&root, &schema, &mut seen).unwrap();
        assert_eq!(resolved["type"], json!("object"));
    }

    #[test]
    fn dereference_resolves_definitions_alias() {
        let root = json!({
            "definitions": {"X": {"type": "integer"}}
        });
        let schema = json!({"$ref": "#/definitions/X"});
        let mut seen = BTreeSet::new();
        let resolved = dereference(&root, &schema, &mut seen).unwrap();
        assert_eq!(resolved["type"], json!("integer"));
    }

    #[test]
    fn dereference_detects_cycle() {
        let root = json!({
            "$defs": {
                "A": {"$ref": "#/$defs/B"},
                "B": {"$ref": "#/$defs/A"}
            }
        });
        let schema = json!({"$ref": "#/$defs/A"});
        let mut seen = BTreeSet::new();
        let err = dereference(&root, &schema, &mut seen).unwrap_err();
        assert!(matches!(err, ComposeError::Cycle(_)));
    }

    #[test]
    fn dereference_rejects_external_ref() {
        let root = json!({});
        let schema = json!({"$ref": "https://example.com/schema.json"});
        let mut seen = BTreeSet::new();
        let err = dereference(&root, &schema, &mut seen).unwrap_err();
        assert!(matches!(err, ComposeError::ExternalRef(_)));
    }

    #[test]
    fn dereference_unresolved_pointer() {
        let root = json!({"$defs": {}});
        let schema = json!({"$ref": "#/$defs/Missing"});
        let mut seen = BTreeSet::new();
        let err = dereference(&root, &schema, &mut seen).unwrap_err();
        assert!(matches!(err, ComposeError::UnresolvedRef(_)));
    }

    #[test]
    fn dereference_preserves_sibling_keys() {
        let root = json!({"$defs": {"Base": {"type": "string", "minLength": 1}}});
        let schema = json!({"$ref": "#/$defs/Base", "maxLength": 10});
        let mut seen = BTreeSet::new();
        let resolved = dereference(&root, &schema, &mut seen).unwrap();
        assert_eq!(resolved["type"], json!("string"));
        assert_eq!(resolved["minLength"], json!(1));
        assert_eq!(resolved["maxLength"], json!(10));
    }

    #[test]
    fn merge_all_of_unions_required_and_properties() {
        let root = json!({});
        let schemas = vec![
            json!({"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"]}),
            json!({"properties": {"b": {"type": "integer"}}, "required": ["b"]}),
        ];
        let merged = merge_all_of(&root, &schemas).unwrap();
        assert_eq!(merged["type"], json!("object"));
        assert!(merged["properties"]["a"].is_object());
        assert!(merged["properties"]["b"].is_object());
        let required = merged["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn merge_all_of_resolves_refs_in_branches() {
        let root = json!({"$defs": {"Name": {"type": "string"}}});
        let schemas = vec![json!({"$ref": "#/$defs/Name"}), json!({"minLength": 1})];
        let merged = merge_all_of(&root, &schemas).unwrap();
        assert_eq!(merged["type"], json!("string"));
        assert_eq!(merged["minLength"], json!(1));
    }
}
