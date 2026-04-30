use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub tool: String,
    pub message: String,
    pub details: String,
    pub repro: ReproInfo,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingKind {
    Crash,
    Hang { ms: u64 },
    SchemaViolation,
    PropertyFailure { invariant: String },
    ProtocolError,
    StateLeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproInfo {
    pub seed: u64,
    pub tool_call: Value,
    pub transport: String,
}

impl Finding {
    pub fn new(
        kind: FindingKind,
        tool: impl Into<String>,
        message: impl Into<String>,
        details: impl Into<String>,
        repro: ReproInfo,
    ) -> Self {
        let tool = tool.into();
        let severity = kind.default_severity();
        let id = finding_id(&tool, &kind, &repro.tool_call);

        Self {
            id,
            kind,
            severity,
            tool,
            message: message.into(),
            details: details.into(),
            repro,
            timestamp: Utc::now(),
        }
    }
}

impl FindingKind {
    pub fn default_severity(&self) -> Severity {
        match self {
            FindingKind::Crash => Severity::Critical,
            FindingKind::Hang { .. } => Severity::High,
            FindingKind::ProtocolError => Severity::High,
            FindingKind::SchemaViolation => Severity::Medium,
            FindingKind::PropertyFailure { .. } => Severity::Medium,
            FindingKind::StateLeak => Severity::High,
        }
    }
}

pub fn finding_id(tool: &str, kind: &FindingKind, tool_call: &Value) -> String {
    let canonical = canonical_json(tool_call);
    let material = format!("{tool}{kind:?}{canonical}");
    let hash = Sha256::digest(material.as_bytes());
    hex::encode(hash)[..16].to_string()
}

pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).expect("canonical JSON serialization")
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let mut ordered = Map::new();
            for (key, value) in entries {
                ordered.insert(key.clone(), canonicalize(value));
            }
            Value::Object(ordered)
        }
        other => other.clone(),
    }
}
