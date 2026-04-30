//! YAML invariants DSL.
//!
//! Phase D introduces:
//!
//! * **Typed operands** — `equals: { lhs: { path: "$.x" }, rhs: { value: 42 } }`
//!   removes the legacy `starts_with('$')` heuristic. The legacy form
//!   (`lhs: "$.x"`) keeps working: a bare string starting with `$` is still
//!   resolved as a path, anything else is a literal.
//! * **Boolean combinators** — `all_of`, `any_of`, `not`.
//! * **`for_each`** — runs child assertions for every node matched by a
//!   wildcard JSONPath.
//! * **`matches_schema`** — validates the value at a path against an inline
//!   JSON Schema using `jsonschema 0.46`.
//! * **Versioning** — `version: 1` and `version: 2` are accepted by the
//!   same parser; v2 unlocks the new constructs above without changing how
//!   v1 files parse.
//!
//! See `tests/fixtures/invariants/*.yaml` for working examples of each
//! construct.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Highest invariant file version this build understands.
pub const MAX_VERSION: u64 = 2;

#[derive(Debug, Error)]
pub enum DslError {
    /// YAML deserialization failed.
    #[error("failed to parse invariants YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    /// `generate` and `fixed` were both set or both omitted on the same
    /// invariant.
    #[error("invariant `{0}` must define exactly one of `generate` or `fixed`")]
    InvalidInputMode(String),
    /// File declared a `version` greater than [`MAX_VERSION`].
    #[error("invariants file declares unsupported version `{0}`; expected ≤ {MAX_VERSION}")]
    UnsupportedVersion(u64),
}

pub type Result<T> = std::result::Result<T, DslError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantFile {
    pub version: u64,
    pub invariants: Vec<Invariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<BTreeMap<String, ValueSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<u32>,
    #[serde(rename = "assert")]
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueSpec {
    #[serde(rename = "type")]
    pub kind: ValueKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<ValueSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
}

/// An operand of a comparison (`equals`, `not_equals`, `at_most`, ...).
///
/// Three forms are accepted, selected by structure:
///
/// 1. `{ path: "$..." }` — explicit JSONPath, resolved against the
///    `{input, response}` context.
/// 2. `{ value: <any> }` — explicit literal.
/// 3. Anything else — bare value. If it's a string starting with `$` we
///    resolve it as a path (legacy v1 behaviour); otherwise it is treated
///    as a literal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Operand {
    /// `{ path: "$..." }`
    Path {
        /// JSONPath expression (RFC 9535 syntax).
        path: String,
    },
    /// `{ value: <any> }`
    Literal {
        /// Verbatim value.
        value: Value,
    },
    /// Anything else: number, boolean, plain object, or string. Strings
    /// starting with `$` are resolved as JSONPath at runtime to preserve
    /// the v1 contract; everything else is treated as a literal.
    Direct(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assertion {
    /// `lhs == rhs` after operand resolution.
    Equals { lhs: Operand, rhs: Operand },
    /// `lhs != rhs` after operand resolution.
    NotEquals { lhs: Operand, rhs: Operand },
    /// Numeric `path <= value`.
    AtMost { path: String, value: Operand },
    /// Numeric `path >= value`.
    AtLeast { path: String, value: Operand },
    /// `len(path) == value` (for arrays / strings).
    LengthEq { path: String, value: Operand },
    /// `len(path) <= value`.
    LengthAtMost { path: String, value: Operand },
    /// `len(path) >= value`.
    LengthAtLeast { path: String, value: Operand },
    /// Type check: the value at `path` has the expected JSON type.
    IsType {
        path: String,
        #[serde(rename = "type")]
        expected: JsonType,
    },
    /// String at `path` matches `pattern` (Rust regex).
    MatchesRegex { path: String, pattern: String },
    /// All child assertions must pass (D1).
    AllOf {
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// At least one child assertion must pass (D1).
    AnyOf {
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// The single child assertion must fail (D1).
    Not {
        /// The assertion that must NOT hold for this invariant to pass.
        assertion: Box<Assertion>,
    },
    /// For every node matched by the wildcard JSONPath, every child
    /// assertion must pass (D3). The current node is exposed as `$.item`
    /// inside the `assert` block; the original input/response remain
    /// accessible via `$.input` / `$.response`.
    ForEach {
        path: String,
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// The value at `path` validates against the inline JSON Schema (D4).
    MatchesSchema {
        path: String,
        /// Inline JSON Schema. Compiled with `jsonschema::validator_for`
        /// at evaluation time.
        schema: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

/// Parses an invariants YAML document.
pub fn parse(source: &str) -> Result<InvariantFile> {
    let file: InvariantFile = serde_yaml::from_str(source)?;
    if file.version > MAX_VERSION {
        return Err(DslError::UnsupportedVersion(file.version));
    }
    for invariant in &file.invariants {
        if invariant.generate.is_some() == invariant.fixed.is_some() {
            return Err(DslError::InvalidInputMode(invariant.name.clone()));
        }
    }
    Ok(file)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn v1_legacy_form_still_parses() {
        let source = r#"
version: 1
invariants:
  - name: demo
    tool: echo
    fixed: { text: hello }
    assert:
      - kind: equals
        lhs: "$.response.text"
        rhs: "$.input.text"
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.version, 1);
        assert_eq!(file.invariants.len(), 1);
        match &file.invariants[0].assertions[0] {
            Assertion::Equals { lhs, rhs } => {
                // Heuristic form: a bare string starting with `$` deserialises
                // into Operand::Direct, and the runner resolves it as a path.
                assert!(matches!(lhs, Operand::Direct(Value::String(s)) if s == "$.response.text"));
                assert!(matches!(rhs, Operand::Direct(Value::String(s)) if s == "$.input.text"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn v2_explicit_operands_parse() {
        let source = r#"
version: 2
invariants:
  - name: demo
    tool: echo
    fixed: { text: hello }
    assert:
      - kind: equals
        lhs: { path: "$.response.text" }
        rhs: { value: hello }
"#;
        let file = parse(source).unwrap();
        match &file.invariants[0].assertions[0] {
            Assertion::Equals { lhs, rhs } => {
                assert!(matches!(lhs, Operand::Path { path } if path == "$.response.text"));
                assert!(
                    matches!(rhs, Operand::Literal { value } if value == &Value::String("hello".into()))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn combinators_round_trip() {
        let source = r#"
version: 2
invariants:
  - name: combinators
    tool: t
    fixed: {}
    assert:
      - kind: all_of
        assert:
          - kind: equals
            lhs: { path: "$.response.a" }
            rhs: { value: 1 }
          - kind: any_of
            assert:
              - kind: at_least
                path: "$.response.b"
                value: { value: 0 }
              - kind: not
                assertion:
                  kind: equals
                  lhs: { path: "$.response.b" }
                  rhs: { value: -1 }
"#;
        let file = parse(source).unwrap();
        let serialized = serde_yaml::to_string(&file).unwrap();
        let reparsed = parse(&serialized).unwrap();
        assert_eq!(reparsed.invariants.len(), 1);
        // Walking down the tree confirms the structure round-tripped.
        let Assertion::AllOf { assertions } = &reparsed.invariants[0].assertions[0] else {
            panic!("expected all_of");
        };
        assert_eq!(assertions.len(), 2);
        assert!(matches!(assertions[1], Assertion::AnyOf { .. }));
    }

    #[test]
    fn for_each_parses() {
        let source = r#"
version: 2
invariants:
  - name: items
    tool: list
    fixed: {}
    assert:
      - kind: for_each
        path: "$.response.items[*]"
        assert:
          - kind: is_type
            path: "$.item.id"
            type: integer
"#;
        let file = parse(source).unwrap();
        let Assertion::ForEach { path, assertions } = &file.invariants[0].assertions[0] else {
            panic!("expected for_each");
        };
        assert_eq!(path, "$.response.items[*]");
        assert_eq!(assertions.len(), 1);
    }

    #[test]
    fn matches_schema_carries_inline_schema() {
        let source = r#"
version: 2
invariants:
  - name: shape
    tool: t
    fixed: {}
    assert:
      - kind: matches_schema
        path: "$.response.user"
        schema:
          type: object
          required: [name]
          properties:
            name: { type: string }
"#;
        let file = parse(source).unwrap();
        let Assertion::MatchesSchema { path, schema } = &file.invariants[0].assertions[0] else {
            panic!("expected matches_schema");
        };
        assert_eq!(path, "$.response.user");
        assert_eq!(schema["type"], Value::String("object".into()));
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required[0], Value::String("name".into()));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let source = r#"
version: 99
invariants: []
"#;
        let err = parse(source).unwrap_err();
        assert!(matches!(err, DslError::UnsupportedVersion(99)));
    }

    #[test]
    fn generate_xor_fixed_is_enforced() {
        let source = r#"
version: 2
invariants:
  - name: bad
    tool: t
    generate: { x: { type: integer, min: 0, max: 1 } }
    fixed: { x: 0 }
    assert: []
"#;
        let err = parse(source).unwrap_err();
        assert!(matches!(err, DslError::InvalidInputMode(_)));
    }
}
