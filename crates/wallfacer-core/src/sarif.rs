use serde_json::{json, Value};

use crate::finding::{Finding, FindingKind, Severity};

pub fn to_sarif(findings: &[Finding], version: &str) -> Value {
    let rules = [
        ("crash", "Server process stopped unexpectedly"),
        ("hang", "Tool call exceeded timeout"),
        ("schema_violation", "Tool response violated output schema"),
        ("property_failure", "Declared property invariant failed"),
        ("protocol_error", "Protocol-level error was observed"),
        (
            "state_leak",
            "State was visible across an expected boundary",
        ),
    ]
    .into_iter()
    .map(|(id, name)| {
        json!({
            "id": id,
            "name": name,
            "shortDescription": { "text": name }
        })
    })
    .collect::<Vec<_>>();

    let results = findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": rule_id(&finding.kind),
                "level": level(finding.severity),
                "message": { "text": finding.message },
                "properties": {
                    "id": finding.id,
                    "tool": finding.tool,
                    "details": finding.details,
                    "repro": finding.repro
                }
            })
        })
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-wallfacer",
                    "version": version,
                    "informationUri": "https://github.com/lacausecrypto/mcp-wallfacer",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn rule_id(kind: &FindingKind) -> &'static str {
    match kind {
        FindingKind::Crash => "crash",
        FindingKind::Hang { .. } => "hang",
        FindingKind::SchemaViolation => "schema_violation",
        FindingKind::PropertyFailure { .. } => "property_failure",
        FindingKind::ProtocolError => "protocol_error",
        FindingKind::StateLeak => "state_leak",
    }
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
