//! Property plan: evaluates YAML invariants against tool responses.

use std::{collections::HashMap, time::Duration};

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
    target::SeverityConfig,
};

use super::{
    destructive::DestructiveDetector,
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
    /// Invariants whose target tool was filtered out as destructive
    /// without an allowlist match. Surfaced for visibility, not as
    /// findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
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
    /// Compiled destructive-tool detector. Invariants targeting a tool
    /// the detector marks destructive (and not allowlisted) are skipped
    /// rather than invoked.
    pub detector: DestructiveDetector,
    /// `[severity]` overrides from `wallfacer.toml`.
    pub severity: SeverityConfig,
}

impl PropertyPlan {
    /// Drives the invariant evaluation loop.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &mut C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<PropertyReport> {
        if self.file.version == 0 || self.file.version > crate::property::dsl::MAX_VERSION {
            bail!("unsupported invariants version {}", self.file.version);
        }

        // Phase I — query the live tool list once and expand every
        // `for_each_tool` block against it. Expanded invariants are
        // appended to the static ones; from this point on the loop
        // doesn't distinguish them. The same listing also feeds the
        // destructive classifier below.
        let live_tools = client
            .list_tools()
            .await
            .context("failed to list tools from MCP server")?;
        let mut all_invariants = self.file.invariants.clone();
        if !self.file.for_each_tool.is_empty() {
            let expanded =
                crate::property::dsl::expand_for_each_tool(&self.file.for_each_tool, &live_tools)
                    .context("failed to expand `for_each_tool` blocks")?;
            all_invariants.extend(expanded);
        }

        // Build a `name -> Tool` map so destructive classification can
        // see annotations (`destructive_hint`, `read_only_hint`) in
        // addition to name-based regex matching.
        let tool_index: HashMap<String, &rmcp::model::Tool> = live_tools
            .iter()
            .map(|tool| (tool.name.to_string(), tool))
            .collect();

        let mut blocked = Vec::new();
        let runnable_invariants: Vec<dsl::Invariant> = all_invariants
            .into_iter()
            .filter(|invariant| {
                let runnable = match tool_index.get(&invariant.tool) {
                    Some(tool) => self.detector.classify(tool).is_runnable(),
                    // Tool not present on the server. Let the runner
                    // surface the failure naturally; classification
                    // doesn't have a Tool struct to inspect.
                    None => true,
                };
                if !runnable {
                    blocked.push(invariant.tool.clone());
                }
                runnable
            })
            .collect();

        let total_cases: u64 = runnable_invariants
            .iter()
            .map(|invariant| invariant.cases.unwrap_or(self.default_cases).max(1) as u64)
            .sum();
        reporter.on_run_start(&RunInfo {
            kind: "property",
            total_iterations: total_cases,
            tools: runnable_invariants
                .iter()
                .map(|invariant| invariant.tool.clone())
                .collect(),
            blocked: blocked.clone(),
            master_seed: Some(self.master_seed),
        });

        let mut report = PropertyReport {
            blocked,
            ..PropertyReport::default()
        };
        for invariant in &runnable_invariants {
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
                    let mut finding = Finding::new(
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
                    if let Some(override_sev) = self.severity.resolve(finding.kind.keyword()) {
                        finding = finding.with_severity(override_sev);
                    }
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
