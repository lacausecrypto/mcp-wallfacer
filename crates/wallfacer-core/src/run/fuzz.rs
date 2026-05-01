//! Fuzz plan: generates payloads for each tool and reports the resulting
//! findings.

use std::time::Duration;

use anyhow::{Context, Result};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::Value;

use crate::{
    client::CallOutcome,
    corpus::Corpus,
    finding::{Finding, FindingKind, ReproInfo},
    mutate::{try_generate_payload, GenMode},
    seed::{derive_seed, derive_seed_canonical},
    target::SeverityConfig,
};

use super::{
    destructive::DestructiveDetector,
    exec::McpExec,
    glob,
    reporter::{Reporter, RunInfo},
};

/// Tools whose schema could not be exercised. Reasons are surfaced from
/// [`crate::mutate::SkipReason`] formatted as a string.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedTool {
    /// Tool name.
    pub tool: String,
    /// Why we gave up (e.g. unresolved `$ref`).
    pub reason: String,
}

/// Outcome of a fuzz run.
///
/// Phase E4: findings are streamed to the corpus and to the reporter
/// during the run; this report carries only counts and the diagnostic
/// lists (skipped, blocked) needed for exit-code logic and post-run
/// summaries. Front-ends that need the findings themselves accumulate
/// them via [`Reporter::on_finding`].
#[derive(Debug, Default, Serialize)]
pub struct FuzzReport {
    /// Number of findings produced during the run.
    pub findings_count: usize,
    /// Tools we could not generate inputs for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedTool>,
    /// Tools that were filtered out as destructive without an allowlist
    /// match. Surfaced for visibility, not as findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
}

/// Returned when a plan runs without errors. Distinct from `FuzzReport`
/// only because dry-run mode does not produce a report.
#[derive(Debug)]
pub enum FuzzOutcome {
    /// Tools that would be fuzzed; produced by [`FuzzPlan::dry_run`].
    DryRun(Vec<String>),
    /// Real fuzz results; produced by [`FuzzPlan::execute`].
    Completed(FuzzReport),
}

/// A reproducible fuzz plan.
#[derive(Debug)]
pub struct FuzzPlan {
    /// Number of payloads generated per tool.
    pub iterations: u64,
    /// Generation mode (Conform / Adversarial / Mixed).
    pub mode: GenMode,
    /// Master seed used to derive per-iteration seeds. The same seed
    /// reproduces the same sequence of payloads.
    pub master_seed: u64,
    /// Glob patterns: empty = match every tool name.
    pub include: Vec<String>,
    /// Glob patterns excluded from the fuzz set. Always honored.
    pub exclude: Vec<String>,
    /// Cap on the number of tools after filtering. `None` = unlimited.
    pub max_tools: Option<usize>,
    /// Timeout applied to each `call_tool`.
    pub timeout: Duration,
    /// Transport label persisted in the [`ReproInfo`]. Plans don't open
    /// the transport themselves, so we receive a stable name (`stdio` /
    /// `http`) from the caller.
    pub transport_name: String,
    /// Compiled destructive-tool detector built from
    /// `[destructive]` + `[allow_destructive]` config.
    pub detector: DestructiveDetector,
    /// `[severity]` overrides from `wallfacer.toml`. Applied to every
    /// produced finding before it lands on disk.
    pub severity: SeverityConfig,
}

impl FuzzPlan {
    /// Returns the tool names that would be fuzzed, for `--dry-run`.
    pub async fn dry_run<C: McpExec + ?Sized>(&self, client: &C) -> Result<Vec<String>> {
        let (tools, _blocked) = self.select_tools(client).await?;
        Ok(tools
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect())
    }

    /// Drives the full fuzz loop, persisting findings to `corpus` and
    /// notifying `reporter` along the way.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &mut C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<FuzzReport> {
        let (tools, blocked) = self.select_tools(client).await?;
        let total = tools.len() as u64 * self.iterations;
        reporter.on_run_start(&RunInfo {
            kind: "fuzz",
            total_iterations: total,
            tools: tools.iter().map(|tool| tool.name.to_string()).collect(),
            blocked: blocked.clone(),
            master_seed: Some(self.master_seed),
        });

        let mut report = FuzzReport {
            findings_count: 0,
            skipped: Vec::new(),
            blocked,
        };

        for tool in tools {
            let tool_name = tool.name.to_string();
            let input_schema = Value::Object((*tool.input_schema).clone());
            for iteration in 0..self.iterations {
                reporter.on_iteration_start(&tool_name, iteration);

                let seed = derive_seed(self.master_seed, &tool_name, iteration);
                let canonical = derive_seed_canonical(self.master_seed, &tool_name, iteration);
                let mut rng = ChaCha20Rng::from_seed(canonical);
                let payload = match try_generate_payload(&input_schema, &mut rng, self.mode) {
                    Ok(payload) => payload,
                    Err(reason) => {
                        let skip = SkippedTool {
                            tool: tool_name.clone(),
                            reason: reason.to_string(),
                        };
                        reporter.on_skipped(&skip.tool, &skip.reason);
                        report.skipped.push(skip);
                        // Bump remaining iterations on the reporter so the
                        // progress bar accounts for the skipped tail.
                        for i in (iteration + 1)..self.iterations {
                            reporter.on_iteration_end(&tool_name, i);
                        }
                        break;
                    }
                };

                let outcome = client
                    .call_tool(&tool_name, payload.value.clone(), self.timeout)
                    .await;
                let kind_message_details: Option<(FindingKind, &str, String)> = match outcome {
                    CallOutcome::Ok(_) => None,
                    CallOutcome::Hang(duration) => Some((
                        FindingKind::Hang {
                            ms: duration.as_millis() as u64,
                        },
                        "tool call timed out",
                        format!("timeout exceeded after {duration:?}"),
                    )),
                    CallOutcome::Crash(reason) => Some((
                        FindingKind::Crash,
                        "server crashed during tool call",
                        reason,
                    )),
                    CallOutcome::ProtocolError(message) => Some((
                        FindingKind::ProtocolError,
                        "protocol error during tool call",
                        message,
                    )),
                };

                if let Some((kind, message, details)) = kind_message_details {
                    let mut finding = Finding::new(
                        kind,
                        &tool_name,
                        message,
                        details,
                        ReproInfo {
                            seed,
                            tool_call: payload.value,
                            transport: self.transport_name.clone(),
                            composition_trail: payload.trail,
                        },
                    );
                    if let Some(override_sev) = self.severity.resolve(finding.kind.keyword()) {
                        finding = finding.with_severity(override_sev);
                    }
                    corpus
                        .write_finding(&finding)
                        .with_context(|| format!("failed to persist finding for `{tool_name}`"))?;
                    reporter.on_finding(&finding);
                    report.findings_count += 1;
                    client.reconnect().await.with_context(|| {
                        format!("failed to reconnect after fault on `{tool_name}`")
                    })?;
                    reporter.on_iteration_end(&tool_name, iteration);
                    break;
                }

                reporter.on_iteration_end(&tool_name, iteration);
            }
        }

        reporter.on_run_end();
        Ok(report)
    }

    async fn select_tools<C: McpExec + ?Sized>(
        &self,
        client: &C,
    ) -> Result<(Vec<rmcp::model::Tool>, Vec<String>)> {
        let all_tools = client
            .list_tools()
            .await
            .context("failed to list tools from MCP server")?;
        let mut blocked = Vec::new();
        let mut tools: Vec<rmcp::model::Tool> = all_tools
            .into_iter()
            .filter(|tool| glob::matches_filters(tool.name.as_ref(), &self.include, &self.exclude))
            .filter(|tool| {
                let classification = self.detector.classify(tool);
                if classification.is_runnable() {
                    true
                } else {
                    blocked.push(tool.name.to_string());
                    false
                }
            })
            .collect();
        if let Some(max_tools) = self.max_tools {
            tools.truncate(max_tools);
        }
        Ok((tools, blocked))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::run::exec::MockClient;
    use crate::run::reporter::NoopReporter;
    use crate::target::{AllowDestructiveConfig, DestructiveConfig};
    use rmcp::model::Tool;
    use serde_json::json;
    use std::sync::Arc;

    fn make_tool(name: &str, schema: Value) -> Tool {
        let map = schema.as_object().cloned().unwrap_or_default();
        Tool::new(name.to_string(), "test tool".to_string(), Arc::new(map))
    }

    fn detector() -> DestructiveDetector {
        DestructiveDetector::from_config(
            &DestructiveConfig::default(),
            &AllowDestructiveConfig::default(),
        )
        .unwrap()
    }

    fn plan(detector: DestructiveDetector) -> FuzzPlan {
        FuzzPlan {
            iterations: 4,
            mode: GenMode::Conform,
            master_seed: 42,
            include: Vec::new(),
            exclude: Vec::new(),
            max_tools: None,
            timeout: Duration::from_secs(1),
            transport_name: "mock".to_string(),
            detector,
            severity: SeverityConfig::default(),
        }
    }

    #[tokio::test]
    async fn fuzz_records_protocol_error_finding_and_reconnects() {
        let tool = make_tool(
            "echo",
            json!({"type": "object", "properties": {"msg": {"type": "string"}}}),
        );
        let mut client = MockClient::new().register(tool, |_args| {
            CallOutcome::ProtocolError("synthetic failure".to_string())
        });

        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("corpus"));
        let mut reporter = NoopReporter;

        let report = plan(detector())
            .execute(&mut client, &corpus, &mut reporter)
            .await
            .unwrap();
        assert_eq!(report.findings_count, 1);
        assert_eq!(client.reconnect_count(), 1);
        assert!(report.skipped.is_empty());
    }

    #[tokio::test]
    async fn fuzz_skips_tools_with_unresolvable_refs() {
        let tool = make_tool(
            "broken",
            json!({"$ref": "https://external.example/schema.json"}),
        );
        let mut client = MockClient::new().register(tool, |_args| {
            CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
        });

        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("corpus"));
        let mut reporter = NoopReporter;

        let report = plan(detector())
            .execute(&mut client, &corpus, &mut reporter)
            .await
            .unwrap();
        assert_eq!(report.findings_count, 0);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("external"));
    }

    #[tokio::test]
    async fn fuzz_blocks_destructive_tools_unless_allowlisted() {
        let destructive_tool = make_tool(
            "delete_user",
            json!({"type": "object", "properties": {"id": {"type": "string"}}}),
        );
        let safe_tool = make_tool(
            "read_user",
            json!({"type": "object", "properties": {"id": {"type": "string"}}}),
        );
        let mut client = MockClient::new()
            .register(destructive_tool, |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            })
            .register(safe_tool, |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            });

        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("corpus"));
        let mut reporter = NoopReporter;
        let report = plan(detector())
            .execute(&mut client, &corpus, &mut reporter)
            .await
            .unwrap();
        assert_eq!(report.blocked, vec!["delete_user".to_string()]);
    }
}
