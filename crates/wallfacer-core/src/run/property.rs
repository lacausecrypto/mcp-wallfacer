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
    glob,
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
    /// Phase AA (v0.8) — cap the live tool list before
    /// `for_each_tool` expansion. `None` = no cap (every tool the
    /// server advertises is fair game). Set to e.g. `Some(5)` to
    /// keep large servers (319-tool sports-hub, 63-tool
    /// mcp-belgium) tractable.
    pub max_tools: Option<usize>,
    /// Phase AA — `globset` patterns selecting which live tools
    /// `for_each_tool` blocks consider. Empty = match every tool.
    pub include_globs: Vec<String>,
    /// Phase AA — `globset` patterns excluded from the live tool
    /// list. Always honoured.
    pub exclude_globs: Vec<String>,
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
        //
        // Phase AA (v0.8) — apply the operator's `--include` /
        // `--exclude` globs and `--max-tools` cap *before* expansion
        // so `for_each_tool` blocks fan out only across the kept
        // set. Tools the operator filtered out simply do not have
        // invariants generated for them; the destructive classifier
        // below still runs against every kept tool.
        let all_live_tools = client
            .list_tools()
            .await
            .context("failed to list tools from MCP server")?;
        let live_tools = apply_tool_filters(
            &all_live_tools,
            &self.include_globs,
            &self.exclude_globs,
            self.max_tools,
        )
        .context("invalid include/exclude glob in property plan")?;
        // v0.8.1 — surface the case where include/exclude/max-tools
        // narrowed the live set to nothing AND the file's only
        // invariants are for_each_tool blocks. Without this, the
        // run reports "0 findings" with exit 0 — a CI gate waiting
        // for findings silently passes when nothing was actually
        // tested. The static `invariants:` list still runs (the
        // filter only applies to `for_each_tool` expansion), so
        // this only fires when the pack is for_each_tool-only.
        if live_tools.is_empty()
            && !all_live_tools.is_empty()
            && self.file.invariants.is_empty()
            && !self.file.for_each_tool.is_empty()
        {
            bail!(
                "every server tool was filtered out by --include / --exclude / --max-tools, \
                 and the pack has no static invariants — nothing would run. Adjust the \
                 filters, or pass --invariants <path> to a pack with static `invariants:` \
                 entries."
            );
        }
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

        // v0.8.1 — dedup `blocked` so the reporter doesn't render
        // the same destructive tool name N times when N invariants
        // happen to target it.
        let mut blocked_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut missing_tools = Vec::new();
        let runnable_invariants: Vec<dsl::Invariant> = all_invariants
            .into_iter()
            .filter(|invariant| match tool_index.get(&invariant.tool) {
                Some(tool) => {
                    let runnable = self.detector.classify(tool).is_runnable();
                    if !runnable {
                        blocked_set.insert(invariant.tool.clone());
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

        let blocked: Vec<String> = blocked_set.into_iter().collect();
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

/// Phase AA — narrow the live tool list before `for_each_tool` expansion.
/// Validates each glob with `glob::compile` so an invalid pattern surfaces
/// once, up-front, rather than silently matching nothing on every tool.
///
/// Empty `includes` matches every tool; `excludes` always wins. `max_tools`
/// truncates after filtering, so the kept set is the first N tools the
/// server advertised in include/exclude order.
fn apply_tool_filters(
    tools: &[rmcp::model::Tool],
    includes: &[String],
    excludes: &[String],
    max_tools: Option<usize>,
) -> Result<Vec<rmcp::model::Tool>> {
    // v0.8.1 — `--max-tools 0` is almost always a typo for
    // `--max-tools <something>` and produces an empty live set.
    // Refuse it explicitly so the operator gets a clear error
    // instead of a quietly-passing CI gate.
    if matches!(max_tools, Some(0)) {
        bail!("--max-tools must be at least 1");
    }
    for pattern in includes.iter().chain(excludes.iter()) {
        glob::compile(pattern).with_context(|| format!("invalid glob pattern `{pattern}`"))?;
    }
    let mut filtered: Vec<rmcp::model::Tool> = tools
        .iter()
        .filter(|tool| glob::matches_filters(tool.name.as_ref(), includes, excludes))
        .cloned()
        .collect();
    // v0.8.1 — if the operator passed --include patterns and none
    // of them matched any live tool, that's almost certainly a
    // typo (`--include cras` for a tool actually called `crash`).
    // Warn loudly so the operator notices before the run reports
    // "0 findings" and exits 0.
    if !includes.is_empty() && !tools.is_empty() && filtered.is_empty() {
        eprintln!(
            "warning: --include patterns {includes:?} matched zero of the {} tools the server \
             advertised. Check for typos; existing tool names: {:?}",
            tools.len(),
            tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>()
        );
    }
    if let Some(cap) = max_tools {
        filtered.truncate(cap);
    }
    Ok(filtered)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::client::CallOutcome;
    use crate::run::exec::MockClient;
    use crate::run::reporter::Reporter;
    use crate::target::{AllowDestructiveConfig, DestructiveConfig};
    use rmcp::model::Tool;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            "test".to_string(),
            Arc::new(serde_json::Map::new()),
        )
    }

    /// Reporter that records every `on_iteration_start` so a test can
    /// assert which tools the plan actually exercised.
    #[derive(Default)]
    struct RecordingReporter {
        tools_seen: HashSet<String>,
    }

    impl Reporter for RecordingReporter {
        fn on_iteration_start(&mut self, tool: &str, _iteration: u64) {
            self.tools_seen.insert(tool.to_string());
        }
    }

    #[test]
    fn empty_filters_keep_every_tool() {
        let tools = vec![tool("a"), tool("b"), tool("c")];
        let kept = apply_tool_filters(&tools, &[], &[], None).expect("filter");
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn max_tools_truncates_after_filtering() {
        let tools = vec![tool("a"), tool("b"), tool("c"), tool("d")];
        let kept = apply_tool_filters(&tools, &[], &[], Some(2)).expect("filter");
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].name.as_ref(), "a");
    }

    #[test]
    fn include_glob_selects_matches() {
        let tools = vec![tool("read_users"), tool("write_users"), tool("read_logs")];
        let kept = apply_tool_filters(&tools, &["read_*".to_string()], &[], None).expect("filter");
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|t| t.name.starts_with("read_")));
    }

    #[test]
    fn exclude_overrides_include() {
        let tools = vec![tool("read_users"), tool("read_secret")];
        let kept = apply_tool_filters(
            &tools,
            &["read_*".to_string()],
            &["read_secret".to_string()],
            None,
        )
        .expect("filter");
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name.as_ref(), "read_users");
    }

    #[test]
    fn invalid_glob_surfaces_error() {
        let tools = vec![tool("a")];
        let err =
            apply_tool_filters(&tools, &["[unterminated".to_string()], &[], None).unwrap_err();
        assert!(err.to_string().contains("invalid glob pattern"));
    }

    #[test]
    fn max_tools_zero_is_rejected() {
        // v0.8.1 — `--max-tools 0` was silently accepted in v0.8,
        // producing an empty live set and a CI gate that quietly
        // exits 0. Reject it explicitly.
        let tools = vec![tool("a"), tool("b")];
        let err = apply_tool_filters(&tools, &[], &[], Some(0)).unwrap_err();
        assert!(err.to_string().contains("--max-tools must be at least 1"));
    }

    #[test]
    fn filter_then_cap() {
        let tools = vec![
            tool("read_a"),
            tool("read_b"),
            tool("read_c"),
            tool("write_a"),
        ];
        let kept =
            apply_tool_filters(&tools, &["read_*".to_string()], &[], Some(2)).expect("filter");
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|t| t.name.starts_with("read_")));
    }

    fn detector() -> DestructiveDetector {
        DestructiveDetector::from_config(
            &DestructiveConfig::default(),
            &AllowDestructiveConfig::default(),
        )
        .expect("default detector")
    }

    fn ok_call(_args: &Value) -> CallOutcome {
        CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
    }

    fn for_each_file() -> dsl::InvariantFile {
        // No-op assertion list keeps the run free of findings while
        // still exercising on_iteration_start once per (tool, case).
        let yaml = r"
version: 3
invariants: []
for_each_tool:
  - name: 'envelope_{{tool_name}}'
    apply:
      cases: 1
      assert: []
";
        dsl::parse(yaml).expect("parse for_each yaml")
    }

    #[tokio::test]
    async fn max_tools_caps_for_each_tool_expansion() {
        // Five tools advertised, cap to two — only two should be exercised.
        let mut client = MockClient::new()
            .register(tool("a"), ok_call)
            .register(tool("b"), ok_call)
            .register(tool("c"), ok_call)
            .register(tool("d"), ok_call)
            .register(tool("e"), ok_call);

        let tmp = tempfile::tempdir().expect("tempdir");
        let corpus = Corpus::new(tmp.path().join("corpus"));
        let mut reporter = RecordingReporter::default();

        let plan = PropertyPlan {
            file: for_each_file(),
            default_cases: 1,
            master_seed: 1,
            timeout: Duration::from_secs(1),
            transport_name: "mock".to_string(),
            detector: detector(),
            severity: SeverityConfig::default(),
            defer_run_end: false,
            max_tools: Some(2),
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
        };

        plan.execute(&mut client, &corpus, &mut reporter)
            .await
            .expect("plan executes");

        assert_eq!(
            reporter.tools_seen.len(),
            2,
            "max_tools=2 should cap expansion; saw {:?}",
            reporter.tools_seen
        );
    }

    #[tokio::test]
    async fn include_glob_narrows_for_each_tool_expansion() {
        let mut client = MockClient::new()
            .register(tool("read_a"), ok_call)
            .register(tool("read_b"), ok_call)
            .register(tool("write_a"), ok_call)
            .register(tool("write_b"), ok_call);

        let tmp = tempfile::tempdir().expect("tempdir");
        let corpus = Corpus::new(tmp.path().join("corpus"));
        let mut reporter = RecordingReporter::default();

        let plan = PropertyPlan {
            file: for_each_file(),
            default_cases: 1,
            master_seed: 1,
            timeout: Duration::from_secs(1),
            transport_name: "mock".to_string(),
            detector: detector(),
            severity: SeverityConfig::default(),
            defer_run_end: false,
            max_tools: None,
            include_globs: vec!["read_*".to_string()],
            exclude_globs: Vec::new(),
        };

        plan.execute(&mut client, &corpus, &mut reporter)
            .await
            .expect("plan executes");

        let seen: Vec<&String> = reporter.tools_seen.iter().collect();
        assert_eq!(reporter.tools_seen.len(), 2, "saw {seen:?}");
        assert!(reporter.tools_seen.iter().all(|t| t.starts_with("read_")));
    }
}
