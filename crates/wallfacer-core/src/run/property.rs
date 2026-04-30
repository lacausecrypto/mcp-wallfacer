//! Property plan: evaluates YAML invariants against tool responses.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    client::CallOutcome,
    corpus::Corpus,
    finding::{Finding, FindingKind, ReproInfo},
    property::{dsl, runner},
    seed::{derive_seed, derive_seed_canonical},
};

use super::{
    exec::McpExec,
    reporter::{Reporter, RunInfo},
};

/// Outcome of a property run.
///
/// Phase E4: findings stream to the corpus and the reporter as they
/// happen; this report carries only the count for exit-code logic.
#[derive(Debug, Default, Serialize)]
pub struct PropertyReport {
    /// Number of invariant failures.
    pub findings_count: usize,
}

/// Property plan.
pub struct PropertyPlan {
    /// Parsed YAML invariant file.
    pub file: dsl::InvariantFile,
    /// Default number of cases per invariant when not overridden in YAML.
    pub default_cases: u32,
    /// Master seed for deriving per-case seeds.
    pub master_seed: u64,
    /// Per-call timeout.
    pub timeout: Duration,
    /// Transport label for `ReproInfo`.
    pub transport_name: String,
}

impl PropertyPlan {
    /// Drives the invariant evaluation loop.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &mut C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<PropertyReport> {
        // Phase D bumped MAX_VERSION to 2; the parser already rejects
        // anything higher than that. Plans accept v1 and v2 transparently.
        if self.file.version == 0 || self.file.version > crate::property::dsl::MAX_VERSION {
            bail!("unsupported invariants version {}", self.file.version);
        }
        let total_cases: u64 = self
            .file
            .invariants
            .iter()
            .map(|invariant| invariant.cases.unwrap_or(self.default_cases).max(1) as u64)
            .sum();
        reporter.on_run_start(&RunInfo {
            kind: "property",
            total_iterations: total_cases,
            tools: self
                .file
                .invariants
                .iter()
                .map(|invariant| invariant.tool.clone())
                .collect(),
            blocked: Vec::new(),
            master_seed: Some(self.master_seed),
        });

        let mut report = PropertyReport::default();
        for invariant in &self.file.invariants {
            let cases = invariant.cases.unwrap_or(self.default_cases).max(1);
            for case_index in 0..cases {
                reporter.on_iteration_start(&invariant.tool, case_index as u64);
                let seed = derive_seed(self.master_seed, &invariant.name, case_index as u64);
                let canonical =
                    derive_seed_canonical(self.master_seed, &invariant.name, case_index as u64);
                let mut rng = ChaCha20Rng::from_seed(canonical);
                let input = runner::input_for_case(invariant, case_index, &mut rng);
                let response = invoke(client, &invariant.tool, input.clone(), self.timeout).await;

                if let Err(error) = runner::evaluate(invariant, input.clone(), response.clone()) {
                    let finding = Finding::new(
                        FindingKind::PropertyFailure {
                            invariant: invariant.name.clone(),
                        },
                        invariant.tool.clone(),
                        "property invariant failed",
                        format!(
                            "{error}\ninput: {}\nresponse: {}",
                            serde_json::to_string_pretty(&input).unwrap_or_default(),
                            serde_json::to_string_pretty(&response).unwrap_or_default(),
                        ),
                        ReproInfo {
                            seed,
                            tool_call: input,
                            transport: self.transport_name.clone(),
                            composition_trail: Vec::new(),
                        },
                    );
                    corpus.write_finding(&finding)?;
                    reporter.on_finding(&finding);
                    report.findings_count += 1;
                    reporter.on_iteration_end(&invariant.tool, case_index as u64);
                    break;
                }
                reporter.on_iteration_end(&invariant.tool, case_index as u64);
            }
        }

        reporter.on_run_end();
        Ok(report)
    }
}

async fn invoke<C: McpExec + ?Sized>(
    client: &mut C,
    tool: &str,
    input: Value,
    timeout: Duration,
) -> Value {
    match client.call_tool(tool, input, timeout).await {
        CallOutcome::Ok(result) => serde_json::to_value(result).unwrap_or(Value::Null),
        CallOutcome::Hang(duration) => {
            client.reconnect().await.ok();
            json!({
                "content": [{"type": "text", "text": format!("timeout after {duration:?}")}],
                "isError": true,
            })
        }
        CallOutcome::Crash(reason) => {
            client.reconnect().await.ok();
            json!({
                "content": [{"type": "text", "text": reason}],
                "isError": true,
            })
        }
        CallOutcome::ProtocolError(message) => {
            client.reconnect().await.ok();
            json!({
                "content": [{"type": "text", "text": message}],
                "isError": true,
            })
        }
    }
}

/// Parses an invariants YAML file into an [`InvariantFile`] for use with
/// [`PropertyPlan`]. Re-exported here so CLI doesn't need to depend on the
/// DSL module directly.
///
/// [`InvariantFile`]: crate::property::dsl::InvariantFile
pub fn parse_invariants(source: &str) -> Result<dsl::InvariantFile> {
    dsl::parse(source).context("failed to parse invariants")
}
