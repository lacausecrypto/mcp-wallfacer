//! Phase L — sequence-aware property runner.
//!
//! A [`crate::property::dsl::Sequence`] is a chain of tool calls
//! sharing a single MCP client and a step-context. Earlier steps can
//! `bind` their `{input, response}` envelope under a name, and later
//! steps reference it via `{{steps.<bind>.<jsonpath>}}` placeholders
//! inside their `with:` arguments.
//!
//! The runner threads bindings through a [`SequenceContext`] map and
//! substitutes placeholders just before invoking each step. This is
//! deliberately late-bound: a step's `with:` block can depend on the
//! *response* of a previous step, not just its inputs.
//!
//! Reconnect semantics — sequences hold per-connection state
//! (authentication tokens, server-side session ids, in-memory
//! bookkeeping). The runner therefore does **not** issue a reconnect
//! when a step's call hangs or returns a protocol error: the sequence
//! is marked failed and the remaining steps are skipped, but the
//! caller's `Client` is left untouched so a subsequent sequence can
//! still observe whatever state the broken step left behind.
//!
//! Findings emitted by this module carry
//! [`crate::finding::FindingKind::SequenceFailure`] tagged with the
//! offending step index; the corpus folder uses the sequence name as
//! the per-finding tool slot so a sequence's findings cluster
//! together.

use std::time::Duration;

use anyhow::Result;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::{
    client::CallOutcome,
    corpus::Corpus,
    finding::{Finding, FindingKind, ReproInfo},
    property::{
        dsl::{FixtureExpect, Sequence, SequenceFixture, StepOutcome},
        jsonpath, runner,
    },
    seed::{derive_seed, derive_seed_canonical},
    target::SeverityConfig,
};

use super::{exec::McpExec, reporter::Reporter};

/// Outcome of a single sequence run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SequenceReport {
    /// Sequences whose every step passed.
    pub passed: Vec<String>,
    /// Number of distinct findings (one per failing sequence).
    pub findings_count: usize,
    /// Sequences skipped because at least one of their steps targeted
    /// a tool the server didn't advertise. The runner refuses to
    /// partially execute a sequence — pre-flight check fails the
    /// whole thing — so the operator sees a single skip per sequence.
    pub skipped_missing_tool: Vec<SkippedSequence>,
}

/// One sequence skipped because of a missing tool.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedSequence {
    /// Sequence name from YAML.
    pub sequence: String,
    /// First missing tool the runner spotted (the sequence may
    /// reference more, but reporting one is enough for triage).
    pub missing_tool: String,
}

/// Plan for executing a batch of [`Sequence`]s.
pub struct SequencePlan {
    /// Sequences to run, in declaration order.
    pub sequences: Vec<Sequence>,
    /// Master seed; per-sequence seeds derive from `master_seed +
    /// sequence_name` deterministically.
    pub master_seed: u64,
    /// Per-step call timeout.
    pub timeout: Duration,
    /// Transport label for [`ReproInfo`].
    pub transport_name: String,
    /// `[severity]` overrides from `wallfacer.toml`.
    pub severity: SeverityConfig,
}

impl SequencePlan {
    /// Drives the sequence loop. Returns once every sequence has
    /// either passed, produced a finding, or been skipped for a
    /// missing tool.
    ///
    /// Lifecycle events (`on_run_start` / `on_run_end`) are *not*
    /// emitted: callers compose this plan with the property plan and
    /// run them through a single reporter instance, so wrapping each
    /// sub-run with its own start/end would split the JSON envelope
    /// and confuse downstream consumers. The reporter sees a clean
    /// stream of `on_finding` / `on_skipped` calls with the sequence
    /// findings interleaved with the single-tool findings.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &mut C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<SequenceReport> {
        let live_tools = client.list_tools().await?;
        let tool_names: std::collections::BTreeSet<String> =
            live_tools.iter().map(|t| t.name.to_string()).collect();

        let mut report = SequenceReport::default();

        for sequence in &self.sequences {
            // Pre-flight: refuse to run a sequence that references a
            // tool the server doesn't advertise. Half-running a
            // sequence would leak state (e.g. the create step fired
            // but the delete step couldn't), which is worse than
            // skipping cleanly.
            if let Some(missing) = sequence
                .steps
                .iter()
                .find(|s| !tool_names.contains(&s.call))
                .map(|s| s.call.clone())
            {
                reporter.on_skipped(
                    &sequence.name,
                    &format!("step calls `{missing}` which the server does not advertise"),
                );
                report.skipped_missing_tool.push(SkippedSequence {
                    sequence: sequence.name.clone(),
                    missing_tool: missing,
                });
                continue;
            }

            reporter.on_iteration_start(&sequence.name, 0);
            let canonical = derive_seed_canonical(self.master_seed, &sequence.name, 0);
            let seed = derive_seed(self.master_seed, &sequence.name, 0);
            let mut rng = ChaCha20Rng::from_seed(canonical);

            let outcome = run_one_sequence(client, sequence, &mut rng, self.timeout).await;
            match outcome {
                SequenceOutcome::Pass => {
                    report.passed.push(sequence.name.clone());
                }
                SequenceOutcome::Fail {
                    step_index,
                    step_call,
                    detail,
                    last_input,
                } => {
                    let mut finding = Finding::new(
                        FindingKind::SequenceFailure {
                            sequence: sequence.name.clone(),
                            step_index,
                            step_call: step_call.clone(),
                        },
                        sequence.name.clone(),
                        format!("sequence `{}` failed at step {step_index}", sequence.name),
                        detail,
                        ReproInfo {
                            seed,
                            tool_call: last_input,
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
                }
            }
            reporter.on_iteration_end(&sequence.name, 0);
        }

        Ok(report)
    }
}

/// Internal result of running a single sequence.
enum SequenceOutcome {
    Pass,
    Fail {
        step_index: usize,
        step_call: String,
        detail: String,
        last_input: Value,
    },
}

/// Executes one [`Sequence`]. Stops at the first failing step and
/// returns the offending step's index plus a free-form detail string.
async fn run_one_sequence<C: McpExec + ?Sized>(
    client: &mut C,
    sequence: &Sequence,
    rng: &mut ChaCha20Rng,
    timeout: Duration,
) -> SequenceOutcome {
    let mut context = SequenceContext::new();

    for (step_index, step) in sequence.steps.iter().enumerate() {
        // Resolve every `{{steps.<bind>.<path>}}` placeholder in the
        // step's `with:` block against the running context. We do this
        // before invoking so that on substitution failure we surface a
        // structural error pointing at the right step.
        let raw_input = step
            .with
            .clone()
            .map(|map| Value::Object(map.into_iter().collect::<Map<_, _>>()))
            .unwrap_or(Value::Object(Map::new()));
        let input = match context.substitute(&raw_input) {
            Ok(value) => value,
            Err(err) => {
                return SequenceOutcome::Fail {
                    step_index,
                    step_call: step.call.clone(),
                    detail: format!(
                        "could not substitute step references in `with:` of step \
                         {step_index}: {err}"
                    ),
                    last_input: raw_input,
                };
            }
        };

        let response = invoke(client, &step.call, input.clone(), timeout, rng).await;

        // Outcome class check (Ok / Error). Only matters when `expect`
        // is set: with the default the runner falls through to the
        // assertion list.
        let expected = step.expect.unwrap_or_default();
        if let Some(detail) = check_step_outcome(&response, expected) {
            return SequenceOutcome::Fail {
                step_index,
                step_call: step.call.clone(),
                detail: format!(
                    "step {step_index} (`{}`) outcome mismatch: {detail}\n\
                     input: {}\nresponse: {}",
                    step.call,
                    serde_json::to_string_pretty(&input).unwrap_or_default(),
                    serde_json::to_string_pretty(&response).unwrap_or_default(),
                ),
                last_input: input,
            };
        }

        // Per-step assertions reuse the existing
        // `runner::evaluate_one` against an `{input, response}`
        // context, exactly like single-tool invariants do.
        if !step.assertions.is_empty() {
            if let Err(err) =
                runner::evaluate_step_assertions(&step.assertions, input.clone(), response.clone())
            {
                return SequenceOutcome::Fail {
                    step_index,
                    step_call: step.call.clone(),
                    detail: format!(
                        "step {step_index} (`{}`) assertion failed: {err}\n\
                         input: {}\nresponse: {}",
                        step.call,
                        serde_json::to_string_pretty(&input).unwrap_or_default(),
                        serde_json::to_string_pretty(&response).unwrap_or_default(),
                    ),
                    last_input: input,
                };
            }
        }

        // Bind the step's envelope so subsequent steps can reference
        // it. Both input and response are exposed under
        // `steps.<bind>.{input,response}`.
        if let Some(bind) = step.bind.as_ref() {
            context.bind(
                bind.clone(),
                json!({
                    "input": input,
                    "response": response,
                }),
            );
        }
    }

    SequenceOutcome::Pass
}

/// Verifies the step's response matches the declared
/// [`StepOutcome`]. Returns `None` on match, `Some(detail)` on
/// mismatch.
fn check_step_outcome(response: &Value, expected: StepOutcome) -> Option<String> {
    let observed_error = response
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match expected {
        StepOutcome::Ok => {
            if observed_error {
                Some("expected ok, observed isError=true".into())
            } else {
                None
            }
        }
        StepOutcome::Error => {
            if observed_error {
                None
            } else {
                Some("expected isError=true, observed ok response".into())
            }
        }
    }
}

/// Per-call invoke wrapper. Mirrors the property runner's
/// `invoke()` but **does not reconnect** on failure: sequences depend
/// on per-connection state surviving across steps.
async fn invoke<C: McpExec + ?Sized>(
    client: &mut C,
    tool: &str,
    input: Value,
    timeout: Duration,
    _rng: &mut ChaCha20Rng,
) -> Value {
    match client.call_tool(tool, input, timeout).await {
        CallOutcome::Ok(result) => serde_json::to_value(result).unwrap_or(Value::Null),
        CallOutcome::Hang(duration) => json!({
            "content": [{"type": "text", "text": format!("timeout after {duration:?}")}],
            "isError": true,
        }),
        CallOutcome::Crash(reason) => json!({
            "content": [{"type": "text", "text": reason}],
            "isError": true,
        }),
        CallOutcome::ProtocolError(message) => json!({
            "content": [{"type": "text", "text": message}],
            "isError": true,
        }),
    }
}

/// Shared per-sequence context. Holds the `{input, response}` envelope
/// of every bound step indexed by bind name, and resolves
/// `{{steps.<bind>.<jsonpath>}}` placeholders inside an arbitrary JSON
/// value tree.
pub struct SequenceContext {
    /// Map of bind name → `{input, response}` envelope.
    bindings: std::collections::BTreeMap<String, Value>,
}

impl Default for SequenceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceContext {
    pub fn new() -> Self {
        Self {
            bindings: Default::default(),
        }
    }

    pub fn bind(&mut self, name: String, envelope: Value) {
        self.bindings.insert(name, envelope);
    }

    /// Walks the JSON tree of `value` and replaces every
    /// `{{steps.<bind>.<jsonpath>}}` placeholder in any string with
    /// the resolved value. Strings that consist of *exactly* one
    /// placeholder become the resolved value (preserving its JSON
    /// type, e.g. number/object). Strings with surrounding text get
    /// the resolved value stringified into the gap.
    pub fn substitute(&self, value: &Value) -> Result<Value, String> {
        match value {
            Value::String(raw) => self.substitute_string(raw),
            Value::Array(items) => items
                .iter()
                .map(|item| self.substitute(item))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), self.substitute(v)?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }

    fn substitute_string(&self, raw: &str) -> Result<Value, String> {
        // Special-case: when the entire string is a single placeholder,
        // preserve the resolved value's native JSON type. This lets
        // sequences pass numbers/objects/arrays to subsequent steps
        // without coercion to JSON-encoded strings.
        if let Some(inner) = single_placeholder(raw) {
            return self.resolve_path(inner);
        }

        // Mixed-text path: replace each placeholder with the resolved
        // value stringified, then return as a String. This handles
        // patterns like `"Bearer {{steps.login.response.structuredContent.token}}"`.
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(idx) = rest.find("{{") {
            out.push_str(&rest[..idx]);
            let after_open = &rest[idx + 2..];
            let close = after_open
                .find("}}")
                .ok_or_else(|| format!("unterminated `{{{{...` in `{raw}`"))?;
            let inner = after_open[..close].trim();
            let resolved = self.resolve_path(inner)?;
            match resolved {
                Value::String(s) => out.push_str(&s),
                other => out.push_str(&other.to_string()),
            }
            rest = &after_open[close + 2..];
        }
        out.push_str(rest);
        Ok(Value::String(out))
    }

    /// Resolves a path of the form `steps.<bind>.<jsonpath>` against
    /// the current bindings.
    fn resolve_path(&self, path: &str) -> Result<Value, String> {
        // Accept both `steps.NAME.X.Y` and `steps.NAME` forms; the
        // latter returns the entire `{input, response}` envelope.
        let inner = path
            .strip_prefix("steps.")
            .ok_or_else(|| format!("placeholder must start with `steps.`: `{path}`"))?;
        let (bind, rest) = inner.split_once('.').unwrap_or((inner, ""));
        let envelope = self
            .bindings
            .get(bind)
            .ok_or_else(|| format!("no step bound under `{bind}` (yet?)"))?;
        if rest.is_empty() {
            return Ok(envelope.clone());
        }
        let jsonpath = format!("$.{rest}");
        jsonpath::resolve_one(envelope, &jsonpath)
            .map_err(|err| format!("resolving `{path}`: {err}"))
    }
}

/// Outcome of evaluating one [`SequenceFixture`] against its parent
/// [`Sequence`]. Mirrors [`runner::FixtureOutcome`] but speaks in
/// step-aware terms so the `pack test` reporter can show which step
/// of which sequence broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceFixtureOutcome {
    /// Observed sequence outcome matches `fixture.expect`.
    Match,
    /// Observed sequence outcome differs from `fixture.expect`.
    Mismatch {
        /// What the fixture promised (`pass`/`fail`).
        expected: FixtureExpect,
        /// What the runner actually observed.
        observed: FixtureExpect,
        /// Free-form detail (assertion message + step index when
        /// applicable).
        detail: String,
    },
    /// Structural error — typically a step-count mismatch between the
    /// sequence's `steps` and the fixture's `responses`.
    Structural {
        /// Free-form description of the structural problem.
        error: String,
    },
}

/// Evaluates one [`SequenceFixture`] against its [`Sequence`] without
/// hitting an MCP server: each step's `with:` map is substituted
/// against the running [`SequenceContext`] just like the live runner
/// does, but the response comes from `fixture.responses[i]` instead
/// of a real call.
pub fn evaluate_sequence_fixture(
    sequence: &Sequence,
    fixture: &SequenceFixture,
) -> SequenceFixtureOutcome {
    if fixture.responses.len() != sequence.steps.len() {
        return SequenceFixtureOutcome::Structural {
            error: format!(
                "fixture provides {} responses but sequence has {} steps",
                fixture.responses.len(),
                sequence.steps.len()
            ),
        };
    }

    let mut context = SequenceContext::new();
    let mut sequence_failed_at: Option<(usize, String)> = None;

    for (step_index, step) in sequence.steps.iter().enumerate() {
        let raw_input = step
            .with
            .clone()
            .map(|map| Value::Object(map.into_iter().collect::<Map<_, _>>()))
            .unwrap_or(Value::Object(Map::new()));
        let input = match context.substitute(&raw_input) {
            Ok(value) => value,
            Err(err) => {
                return SequenceFixtureOutcome::Structural {
                    error: format!(
                        "could not substitute step references in step {step_index}: {err}"
                    ),
                };
            }
        };
        let response = fixture.responses[step_index].clone();

        let expected = step.expect.unwrap_or_default();
        if let Some(detail) = check_step_outcome(&response, expected) {
            sequence_failed_at = Some((step_index, format!("outcome mismatch: {detail}")));
            break;
        }

        if !step.assertions.is_empty() {
            if let Err(err) =
                runner::evaluate_step_assertions(&step.assertions, input.clone(), response.clone())
            {
                sequence_failed_at = Some((step_index, format!("assertion failed: {err}")));
                break;
            }
        }

        if let Some(bind) = step.bind.as_ref() {
            context.bind(
                bind.clone(),
                json!({
                    "input": input,
                    "response": response,
                }),
            );
        }
    }

    let observed = if sequence_failed_at.is_some() {
        FixtureExpect::Fail
    } else {
        FixtureExpect::Pass
    };

    if observed == fixture.expect {
        SequenceFixtureOutcome::Match
    } else {
        let detail = sequence_failed_at
            .map(|(idx, msg)| format!("step {idx}: {msg}"))
            .unwrap_or_else(|| "all steps passed".to_string());
        SequenceFixtureOutcome::Mismatch {
            expected: fixture.expect,
            observed,
            detail,
        }
    }
}

/// Returns `Some(inner)` when `raw` is exactly `{{ ... }}` with no
/// surrounding text. The trimmed inner expression is returned.
fn single_placeholder(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    let inner = trimmed.strip_prefix("{{")?.strip_suffix("}}")?;
    // Reject placeholders that *contain* another `{{...}}` — those are
    // mixed-text expressions that need the slow path.
    if inner.contains("{{") || inner.contains("}}") {
        return None;
    }
    Some(inner.trim())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn single_placeholder_preserves_type() {
        let mut ctx = SequenceContext::new();
        ctx.bind(
            "login".into(),
            json!({"input": {}, "response": {"structuredContent": {"id": 42}}}),
        );
        let out = ctx
            .substitute(&json!("{{steps.login.response.structuredContent.id}}"))
            .unwrap();
        assert_eq!(out, json!(42));
    }

    #[test]
    fn mixed_text_substitutes_inline() {
        let mut ctx = SequenceContext::new();
        ctx.bind(
            "login".into(),
            json!({"input": {}, "response": {"structuredContent": {"token": "abc"}}}),
        );
        let out = ctx
            .substitute(&json!(
                "Bearer {{steps.login.response.structuredContent.token}}"
            ))
            .unwrap();
        assert_eq!(out, json!("Bearer abc"));
    }

    #[test]
    fn unknown_step_surfaces_error() {
        let ctx = SequenceContext::new();
        let err = ctx.substitute(&json!("{{steps.missing.x}}")).unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn unterminated_placeholder_errors() {
        let mut ctx = SequenceContext::new();
        ctx.bind("a".into(), json!({}));
        let err = ctx.substitute(&json!("hello {{steps.a")).unwrap_err();
        assert!(err.contains("unterminated"));
    }

    #[test]
    fn step_outcome_ok_default_passes_when_no_is_error() {
        let r = json!({"content": [{"type": "text", "text": "ok"}]});
        assert!(check_step_outcome(&r, StepOutcome::Ok).is_none());
    }

    #[test]
    fn step_outcome_error_passes_when_is_error_true() {
        let r = json!({"isError": true, "content": []});
        assert!(check_step_outcome(&r, StepOutcome::Error).is_none());
    }

    #[test]
    fn step_outcome_mismatch_returns_detail() {
        let r = json!({"isError": true, "content": []});
        assert!(check_step_outcome(&r, StepOutcome::Ok).is_some());
    }
}
