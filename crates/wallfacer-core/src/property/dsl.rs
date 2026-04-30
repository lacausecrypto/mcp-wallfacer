use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DslError {
    #[error("failed to parse invariants YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invariant `{0}` must define exactly one of `generate` or `fixed`")]
    InvalidInputMode(String),
}

pub type Result<T> = std::result::Result<T, DslError>;

#[derive(Debug, Clone, Deserialize)]
pub struct InvariantFile {
    pub version: u64,
    pub invariants: Vec<Invariant>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub tool: String,
    pub generate: Option<BTreeMap<String, ValueSpec>>,
    pub fixed: Option<BTreeMap<String, Value>>,
    pub cases: Option<u32>,
    #[serde(rename = "assert")]
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValueSpec {
    #[serde(rename = "type")]
    pub kind: ValueKind,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub items: Option<Box<ValueSpec>>,
    pub min_items: Option<usize>,
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assertion {
    Equals {
        lhs: Value,
        rhs: Value,
    },
    NotEquals {
        lhs: Value,
        rhs: Value,
    },
    AtMost {
        path: String,
        value: Value,
    },
    AtLeast {
        path: String,
        value: Value,
    },
    LengthEq {
        path: String,
        value: Value,
    },
    LengthAtMost {
        path: String,
        value: Value,
    },
    LengthAtLeast {
        path: String,
        value: Value,
    },
    IsType {
        path: String,
        #[serde(rename = "type")]
        expected: JsonType,
    },
    MatchesRegex {
        path: String,
        pattern: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
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

pub fn parse(source: &str) -> Result<InvariantFile> {
    let file: InvariantFile = serde_yaml::from_str(source)?;
    for invariant in &file.invariants {
        if invariant.generate.is_some() == invariant.fixed.is_some() {
            return Err(DslError::InvalidInputMode(invariant.name.clone()));
        }
    }
    Ok(file)
}
