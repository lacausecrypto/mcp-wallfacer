//! Differential plan: compares observed tool responses with declared or
//! learned output schemas.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use jsonschema::validator_for;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::Value;

use crate::{
    client::CallOutcome,
    corpus::Corpus,
    differential::{boundary_payload, load_schema, response_value, save_schema},
    finding::{Finding, FindingKind, ReproInfo, Severity},
    mutate::{generate_payload, GenMode},
    seed::{derive_seed, derive_seed_canonical},
};

use super::{
    exec::McpExec,
    reporter::{Reporter, RunInfo},
};

/// Outcome of a differential run.
///
/// Phase E4: findings stream to the corpus and the reporter; the report
/// itself only carries counts and the diagnostic lists.
#[derive(Debug, Default, Serialize)]
pub struct DifferentialReport {
    /// Number of schema-violation findings produced.
    pub findings_count: usize,
    /// Highest severity encountered across the run; used by `wallfacer ci`
    /// to gate exit codes on a configurable threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
    /// Tools without a declared or learned output schema; surfaced for
    /// visibility, not as findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_schema: Vec<String>,
    /// Tools whose declared output schema failed to compile.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invalid_schema: Vec<String>,
}

/// Differential plan.
pub struct DifferentialPlan {
    /// When `true`, persist declared output schemas as inferred baselines
    /// and stop. No tools are exercised.
    pub learn: bool,
    /// Iterations per tool when not learning.
    pub iterations: u64,
    /// Master seed for deriving payload seeds.
    pub master_seed: u64,
    /// Where inferred schemas live on disk.
    pub schema_dir: PathBuf,
    /// Per-call timeout.
    pub timeout: Duration,
    /// Transport label for `ReproInfo`.
    pub transport_name: String,
}

impl DifferentialPlan {
    /// Persist declared output schemas as baselines. Returns the number of
    /// schemas written.
    pub async fn learn<C: McpExec + ?Sized>(&self, client: &C) -> Result<usize> {
        let tools = client
            .list_tools()
            .await
            .context("failed to list tools from MCP server")?;
        let mut count = 0;
        for tool in &tools {
            if let Some(schema) = &tool.output_schema {
                let schema = Value::Object((**schema).clone());
                save_schema(&self.schema_dir, tool.name.as_ref(), &schema)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Drives the differential check loop.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &mut C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<DifferentialReport> {
        let tools = client
            .list_tools()
            .await
            .context("failed to list tools from MCP server")?;
        reporter.on_run_start(&RunInfo {
            kind: "differential",
            total_iterations: tools.len() as u64 * self.iterations,
            tools: tools.iter().map(|t| t.name.to_string()).collect(),
            blocked: Vec::new(),
            master_seed: Some(self.master_seed),
        });

        let mut report = DifferentialReport::default();

        for tool in &tools {
            let tool_name = tool.name.to_string();
            let schema = match &tool.output_schema {
                Some(schema) => Some(Value::Object((**schema).clone())),
                None => load_schema(&self.schema_dir, tool.name.as_ref())?,
            };
            let Some(schema) = schema else {
                report.missing_schema.push(tool_name.clone());
                reporter.on_skipped(&tool_name, "no declared or learned output schema");
                continue;
            };
            let validator = match validator_for(&schema) {
                Ok(v) => v,
                Err(_) => {
                    report.invalid_schema.push(tool_name.clone());
                    reporter.on_skipped(&tool_name, "output schema does not compile");
                    continue;
                }
            };
            let input_schema = Value::Object((*tool.input_schema).clone());
            for iteration in 0..self.iterations {
                reporter.on_iteration_start(&tool_name, iteration);
                let seed = derive_seed(self.master_seed, &tool_name, iteration);
                let payload = if iteration == 0 {
                    boundary_payload(&input_schema)
                } else {
                    let canonical = derive_seed_canonical(self.master_seed, &tool_name, iteration);
                    let mut rng = ChaCha20Rng::from_seed(canonical);
                    generate_payload(&input_schema, &mut rng, GenMode::Conform)
                };

                let outcome = client
                    .call_tool(&tool_name, payload.clone(), self.timeout)
                    .await;
                let mut should_break = false;
                match outcome {
                    CallOutcome::Ok(result) if result.is_error == Some(true) => {}
                    CallOutcome::Ok(result) => {
                        let response = response_value(&result);
                        let errors = validator
                            .iter_errors(&response)
                            .map(|err| format!("{err} at instance path {}", err.instance_path()))
                            .collect::<Vec<_>>();
                        if !errors.is_empty() {
                            let finding = Finding::new(
                                FindingKind::SchemaViolation,
                                tool_name.clone(),
                                "tool response does not match output schema",
                                format!(
                                    "{}\nobserved: {}",
                                    errors.join("\n"),
                                    serde_json::to_string_pretty(&response).unwrap_or_default()
                                ),
                                ReproInfo {
                                    seed,
                                    tool_call: payload,
                                    transport: self.transport_name.clone(),
                                    composition_trail: Vec::new(),
                                },
                            );
                            corpus.write_finding(&finding)?;
                            reporter.on_finding(&finding);
                            report.findings_count += 1;
                            report.max_severity =
                                Some(report.max_severity.map_or(finding.severity, |current| {
                                    current.max(finding.severity)
                                }));
                            should_break = true;
                        }
                    }
                    CallOutcome::Hang(_)
                    | CallOutcome::Crash(_)
                    | CallOutcome::ProtocolError(_) => {
                        client.reconnect().await.ok();
                        should_break = true;
                    }
                }
                reporter.on_iteration_end(&tool_name, iteration);
                if should_break {
                    break;
                }
            }
        }

        reporter.on_run_end();
        Ok(report)
    }
}
