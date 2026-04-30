//! Thin façade over [`serde_json_path`] (RFC 9535) preserving the legacy
//! `resolve` / `resolve_one` API used by the property runner.
//!
//! Phase B1: this module no longer parses paths itself. We delegate to the
//! `serde_json_path` crate and just adapt the result types and errors.

use serde_json::Value;
use thiserror::Error;

/// Errors returned by path resolution.
#[derive(Debug, Error)]
pub enum JsonPathError {
    /// The path string is not valid RFC 9535 JSONPath syntax.
    #[error("invalid JSONPath `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json_path::ParseError,
    },
    /// The path parsed successfully but resolved to nothing in the document.
    #[error("path `{0}` did not resolve to any value")]
    Missing(String),
}

pub type Result<T> = std::result::Result<T, JsonPathError>;

/// Resolves all matches for a JSONPath expression. Returns an owned vector;
/// callers retain no borrow on `root`.
pub fn resolve(root: &Value, path: &str) -> Result<Vec<Value>> {
    let parsed = serde_json_path::JsonPath::parse(path).map_err(|source| JsonPathError::Parse {
        path: path.to_string(),
        source,
    })?;
    Ok(parsed
        .query(root)
        .all()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>())
}

/// Resolves a JSONPath expression and returns the first match. Returns
/// [`JsonPathError::Missing`] if the path resolved to zero nodes.
pub fn resolve_one(root: &Value, path: &str) -> Result<Value> {
    let nodes = resolve(root, path)?;
    nodes
        .into_iter()
        .next()
        .ok_or_else(|| JsonPathError::Missing(path.to_string()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_nested_field() {
        let root = json!({"a": {"b": 42}});
        assert_eq!(resolve_one(&root, "$.a.b").unwrap(), json!(42));
    }

    #[test]
    fn resolves_array_index() {
        let root = json!({"items": [10, 20, 30]});
        assert_eq!(resolve_one(&root, "$.items[1]").unwrap(), json!(20));
    }

    #[test]
    fn resolves_wildcard_in_middle() {
        // RFC 9535 supports wildcards anywhere; the previous home-grown parser
        // forbade non-final wildcards. This is a regression test that the new
        // backend lifts that limit.
        let root = json!({"items": [{"v": 1}, {"v": 2}, {"v": 3}]});
        let values = resolve(&root, "$.items[*].v").unwrap();
        assert_eq!(values, vec![json!(1), json!(2), json!(3)]);
    }

    #[test]
    fn missing_returns_missing_error() {
        let root = json!({"a": 1});
        let err = resolve_one(&root, "$.nope").unwrap_err();
        assert!(matches!(err, JsonPathError::Missing(_)));
    }

    #[test]
    fn invalid_syntax_returns_parse_error() {
        let root = json!({});
        let err = resolve(&root, "not-a-path").unwrap_err();
        assert!(matches!(err, JsonPathError::Parse { .. }));
    }

    #[test]
    fn filter_expression_works() {
        let root = json!({"items": [{"v": 1}, {"v": 2}, {"v": 3}]});
        let values = resolve(&root, "$.items[?@.v > 1].v").unwrap();
        assert_eq!(values, vec![json!(2), json!(3)]);
    }
}
