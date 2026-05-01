//! Local payload unredaction shared by `wallfacer replay` and `wallfacer
//! corpus replay`.
//!
//! Persisted findings carry `<redacted>` placeholders for any payload
//! field that matched a sensitive key (see `redact::is_sensitive_key`).
//! Replaying needs the real values back; we look them up in the
//! environment under `WALLFACER_REPLAY_<KEY_UPPER>` so secrets stay in
//! the developer's shell rather than landing in the corpus.

use serde_json::{Map, Value};
use wallfacer_core::redact::REDACTED_PLACEHOLDER;

/// Walks `value` and replaces every `<redacted>` string with the value
/// of `WALLFACER_REPLAY_<KEY_UPPER>`, where `KEY` is the parent JSON
/// object key (e.g. `password` → `WALLFACER_REPLAY_PASSWORD`).
///
/// Returns the substituted payload and the list of keys that had no
/// matching env var (so callers can print a friendly note pointing at
/// what's missing).
pub fn unredact(value: &Value) -> (Value, Vec<String>) {
    let mut missing = Vec::new();
    let substituted = walk(value, &mut missing);
    (substituted, missing)
}

fn walk(value: &Value, missing: &mut Vec<String>) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, child) in map {
                let new_value = if is_placeholder(child) {
                    let env_var = format!("WALLFACER_REPLAY_{}", key.to_ascii_uppercase());
                    match std::env::var(&env_var) {
                        Ok(v) => Value::String(v),
                        Err(_) => {
                            missing.push(key.clone());
                            child.clone()
                        }
                    }
                } else {
                    walk(child, missing)
                };
                out.insert(key.clone(), new_value);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|item| walk(item, missing)).collect()),
        other => other.clone(),
    }
}

fn is_placeholder(value: &Value) -> bool {
    matches!(value, Value::String(s) if s == REDACTED_PLACEHOLDER)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn substitutes_from_env() {
        std::env::set_var("WALLFACER_REPLAY_PASSWORD", "real-secret");
        std::env::set_var("WALLFACER_REPLAY_API_KEY", "real-key");
        let input = json!({
            "user": "alice",
            "password": "<redacted>",
            "api_key": "<redacted>"
        });
        let (output, missing) = unredact(&input);
        assert_eq!(output["user"], json!("alice"));
        assert_eq!(output["password"], json!("real-secret"));
        assert_eq!(output["api_key"], json!("real-key"));
        assert!(missing.is_empty());
    }

    #[test]
    fn reports_missing_env_vars() {
        std::env::remove_var("WALLFACER_REPLAY_TOKEN");
        let input = json!({"token": "<redacted>", "name": "alice"});
        let (output, missing) = unredact(&input);
        assert_eq!(output["token"], json!("<redacted>"));
        assert_eq!(missing, vec!["token".to_string()]);
    }

    #[test]
    fn walks_nested_objects_and_arrays() {
        std::env::set_var("WALLFACER_REPLAY_PASSWORD", "real-secret");
        let input = json!({
            "users": [
                {"name": "alice", "password": "<redacted>"},
                {"name": "bob", "password": "<redacted>"}
            ]
        });
        let (output, _) = unredact(&input);
        assert_eq!(output["users"][0]["password"], json!("real-secret"));
        assert_eq!(output["users"][1]["password"], json!("real-secret"));
    }
}
