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
    mutate::{generate_payload, GenMode},
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
    /// Invariants whose target tool was not present on the server.
    /// Typically a pack's default `witness_tool` parameter that doesn't
    /// match this particular target's tool catalog. Surfaced as a
    /// `(tool, invariant)` pair so the operator can either override the
    /// pack parameter or accept the gap.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_tools: Vec<MissingTool>,
}

/// One invariant skipped because its target tool is not advertised by
/// the server. Reporter surfaces this distinct from `blocked` so the
/// operator can tell pack-parameter mismatches apart from
/// destructive-guard skips.
#[derive(Debug, Clone, Serialize)]
pub struct MissingTool {
    /// Invariant name (post `for_each_tool` expansion).
    pub invariant: String,
    /// Tool name that the invariant targeted but the server didn't
    /// advertise.
    pub tool: String,
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
    /// When `true`, suppress the trailing `reporter.on_run_end()` so
    /// the caller can chain another sub-run (typically a
    /// [`super::SequencePlan`]) into the same reporter without
    /// flushing the findings table early. Defaults to `false` —
    /// stand-alone property runs keep their existing lifecycle.
    #[doc(hidden)]
    pub defer_run_end: bool,
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
        let mut missing_tools = Vec::new();
        let runnable_invariants: Vec<dsl::Invariant> = all_invariants
            .into_iter()
            .filter(|invariant| match tool_index.get(&invariant.tool) {
                Some(tool) => {
                    let runnable = self.detector.classify(tool).is_runnable();
                    if !runnable {
                        blocked.push(invariant.tool.clone());
                    }
                    runnable
                }
                None => {
                    // Tool not advertised by the server. Skipping rather
                    // than invoking it is safer than letting the runner
                    // hammer reconnect on every "method not found":
                    // packs ship default `witness_tool` parameters that
                    // legitimately don't apply to every target.
                    missing_tools.push(MissingTool {
                        invariant: invariant.name.clone(),
                        tool: invariant.tool.clone(),
                    });
                    false
                }
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
        // Surface every skipped invariant to the reporter so JSON
        // consumers see them under `skipped` and the human reporter
        // prints a "Skipped tool" row.
        for missing in &missing_tools {
            reporter.on_skipped(
                &missing.tool,
                &format!(
                    "not advertised by server (invariant `{}`)",
                    missing.invariant
                ),
            );
        }

        let mut report = PropertyReport {
            blocked,
            missing_tools,
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
                // `input: schema_valid` overrides `fixed`/`generate` and
                // pulls a payload conforming to the live tool's input
                // schema. Falls back to the static input pipeline when
                // the schema isn't usable (e.g. unresolved $ref) or
                // when the tool isn't in `tool_index` — the latter
                // shouldn't happen because missing tools are filtered
                // earlier, but we handle it defensively.
                let input = if invariant.input == Some(dsl::InputMode::SchemaValid) {
                    tool_index
                        .get(&invariant.tool)
                        .and_then(|tool| {
                            let schema = serde_json::to_value(tool.input_schema.as_ref()).ok()?;
                            Some(generate_payload(&schema, &mut rng, GenMode::Conform))
                        })
                        .unwrap_or_else(|| runner::input_for_case(invariant, case_index, &mut rng))
                } else {
                    runner::input_for_case(invariant, case_index, &mut rng)
                };
                let response = invoke(client, &invariant.tool, input.clone(), self.timeout).await;

                let live_tool = tool_index.get(&invariant.tool).copied();
                if let Err(error) = runner::evaluate_with_tool(
                    invariant,
                    input.clone(),
                    response.clone(),
                    live_tool,
                ) {
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

        if !self.defer_run_end {
            reporter.on_run_end();
        }
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
