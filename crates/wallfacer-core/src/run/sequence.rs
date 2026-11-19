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
    fuzz_corpus::{response_fingerprint, CorpusTrigger, FuzzCorpus, FuzzCorpusEntry},
    mutate::corpus_mutator,
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
    /// Sequences that could not run to a verdict because a precondition
    /// step failed (see [`crate::property::dsl::SequenceStep::expect`]).
    pub inconclusive: Vec<InconclusiveSequence>,
}

/// One sequence whose setup did not succeed.
#[derive(Debug, Clone, Serialize)]
pub struct InconclusiveSequence {
    pub sequence: String,
    pub step_index: usize,
    pub reason: String,
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
    /// Phase V — optional persistent corpus, shared with the v0.6
    /// fuzzer. When set, sequence steps mutate from the corpus
    /// `mutate_ratio` fraction of the time and save inputs that
    /// trigger findings or produce a previously-unseen response
    /// fingerprint per step. Cross-pollinates with `wallfacer fuzz
    /// --corpus-feedback`: fuzz-discovered "interesting ids" can
    /// seed sequence steps that call the same tool.
    pub fuzz_corpus: Option<crate::fuzz_corpus::FuzzCorpus>,
    /// Phase V — fraction of sequence-step inputs that mutate from
    /// the corpus instead of using the YAML literal verbatim.
    /// Range `0.0..=1.0`. Default `0.9` matches the fuzz default.
    /// Ignored when [`Self::fuzz_corpus`] is `None` or the per-tool
    /// corpus is empty.
    pub mutate_ratio: f64,
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

        // Phase V — preload the response-fingerprint set from
        // every prior corpus entry across the tools this batch of
        // sequences calls into. A novel fingerprint at run time is
        // one not present in this set.
        let mut seen_fingerprints: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        if let Some(corpus_ref) = self.fuzz_corpus.as_ref() {
            let touched_tools: std::collections::BTreeSet<&str> = self
                .sequences
                .iter()
                .flat_map(|s| s.steps.iter().map(|st| st.call.as_str()))
                .collect();
            for tool in touched_tools {
                if let Ok(entries) = corpus_ref.list(tool) {
                    for e in entries {
                        seen_fingerprints.insert(e.fingerprint);
                    }
                }
            }
        }

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

            let outcome = run_one_sequence(
                client,
                sequence,
                &mut rng,
                self.timeout,
                self.fuzz_corpus.as_ref(),
                self.mutate_ratio,
                &mut seen_fingerprints,
            )
            .await;
            match outcome {
                SequenceOutcome::Pass => {
                    report.passed.push(sequence.name.clone());
                }
                SequenceOutcome::Inconclusive { step_index, reason } => {
                    reporter.on_skipped(
                        &sequence.name,
                        &format!("inconclusive: precondition step {step_index} failed ({reason})"),
                    );
                    report.inconclusive.push(InconclusiveSequence {
                        sequence: sequence.name.clone(),
                        step_index,
                        reason,
                    });
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
    /// A precondition step (no explicit `expect`) returned an error, or a
    /// later step referenced a value that setup step never produced. The
    /// sequence didn't get to test anything: reported as skipped.
    Inconclusive {
        step_index: usize,
        reason: String,
    },
    Fail {
        step_index: usize,
        step_call: String,
        detail: String,
        last_input: Value,
    },
}

/// Executes one [`Sequence`]. Stops at the first failing step and
/// returns the offending step's index plus a free-form detail string.
///
/// Phase V — when `corpus` is `Some`, the runner mutates each
/// step's `with:` block from the per-tool corpus
/// `mutate_ratio` fraction of the time and saves any input that
/// triggered a finding *or* produced a previously-unseen response
/// fingerprint.
async fn run_one_sequence<C: McpExec + ?Sized>(
    client: &mut C,
    sequence: &Sequence,
    rng: &mut ChaCha20Rng,
    timeout: Duration,
    corpus: Option<&FuzzCorpus>,
    mutate_ratio: f64,
    seen_fingerprints: &mut std::collections::BTreeSet<String>,
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
        let substituted = match context.substitute(&raw_input) {
            Ok(value) => value,
            // An earlier step succeeded but didn't return the value this
            // step needs (e.g. no `structuredContent.id`): the sequence
            // can't proceed, which says nothing about the server's state.
            Err(err) => {
                return SequenceOutcome::Inconclusive {
                    step_index,
                    reason: format!("step references did not resolve: {err}"),
                };
            }
        };

        // Phase V — 90/10 mutate-vs-literal split. We mutate the
        // *substituted* input so step-references already point at
        // real bound values; mutation rolls dice on top, the
        // bindings stay coherent. When the corpus has no entry
        // for this step's tool, fall back to the literal input.
        use rand::Rng;
        let prior: Vec<FuzzCorpusEntry> = corpus
            .map(|c| c.list(&step.call).unwrap_or_default())
            .unwrap_or_default();
        let input = if !prior.is_empty() && rng.gen_bool(mutate_ratio.clamp(0.0, 1.0)) {
            // Pick a random corpus entry, mutate it. The seed
            // input is whatever the past run found interesting;
            // current substituted input is ignored on this path
            // — by design, that's how we explore beyond the
            // hand-written YAML.
            let pick = &prior[rng.gen_range(0..prior.len())];
            corpus_mutator::mutate(&pick.input, rng)
        } else {
            substituted.clone()
        };

        let response = match invoke(client, &step.call, input.clone(), timeout, rng).await {
            Ok(response) => response,
            Err(transport) => {
                return SequenceOutcome::Fail {
                    step_index,
                    step_call: step.call.clone(),
                    detail: format!(
                        "step {step_index} (`{}`) transport failure: {transport}\ninput: {}",
                        step.call,
                        serde_json::to_string_pretty(&input).unwrap_or_default(),
                    ),
                    last_input: input,
                };
            }
        };

        // Phase V — fingerprint the response BEFORE we destructure
        // it for outcome / assertion checks below. Save the input
        // when the fingerprint is novel.
        let fingerprint = response_fingerprint(&response);
        if let Some(corpus_ref) = corpus {
            if seen_fingerprints.insert(fingerprint.clone()) {
                let _ = corpus_ref.save(&FuzzCorpusEntry {
                    tool: step.call.clone(),
                    input: input.clone(),
                    trigger: CorpusTrigger::NewFingerprint,
                    fingerprint: fingerprint.clone(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        // Phase V — helper that saves the failing step's input
        // under the strongest signal (`Finding`). Overrides any
        // earlier `NewFingerprint` save for the same input via the
        // corpus's input-key dedup.
        let save_finding = |corpus_ref: &FuzzCorpus, fingerprint: &str, input: &Value| {
            let _ = corpus_ref.save(&FuzzCorpusEntry {
                tool: step.call.clone(),
                input: input.clone(),
                trigger: CorpusTrigger::Finding {
                    kind: "sequence_failure".to_string(),
                },
                fingerprint: fingerprint.to_string(),
                timestamp: chrono::Utc::now(),
            });
        };

        // Outcome class check (Ok / Error). Only matters when `expect`
        // is set: with the default the runner falls through to the
        // assertion list.
        if step.expect.is_none() && check_step_outcome(&response, StepOutcome::Ok).is_some() {
            return SequenceOutcome::Inconclusive {
                step_index,
                reason: format!("`{}` returned isError", step.call),
            };
        }
        let expected = step.expect.unwrap_or_default();
        if let Some(detail) = check_step_outcome(&response, expected) {
            if let Some(c) = corpus {
                save_finding(c, &fingerprint, &input);
            }
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
                if let Some(c) = corpus {
                    save_finding(c, &fingerprint, &input);
                }
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
///
/// A hang, crash or protocol error is returned as `Err` and fails the
/// sequence. It must never be rewritten into an `isError: true`
/// envelope: a step that `expect: error` would then count a crashed
/// server as the expected rejection.
async fn invoke<C: McpExec + ?Sized>(
    client: &mut C,
    tool: &str,
    input: Value,
    timeout: Duration,
    _rng: &mut ChaCha20Rng,
) -> std::result::Result<Value, String> {
    match client.call_tool(tool, input, timeout).await {
        CallOutcome::Ok(result) => Ok(serde_json::to_value(result).unwrap_or(Value::Null)),
        CallOutcome::Hang(duration) => Err(format!("hang: no response after {duration:?}")),
        CallOutcome::Crash(reason) => Err(format!("crash: {reason}")),
        CallOutcome::ProtocolError(message) => Err(format!("protocol error: {message}")),
        // A JSON-RPC error reply is a rejection the step can expect.
        CallOutcome::JsonRpcError { code, message } => Ok(
            crate::run::property::json_rpc_error_envelope(code, &message),
        ),
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
    let mut inconclusive_at: Option<usize> = None;

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

        if step.expect.is_none() && check_step_outcome(&response, StepOutcome::Ok).is_some() {
            inconclusive_at = Some(step_index);
            break;
        }
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

    let observed = if inconclusive_at.is_some() {
        FixtureExpect::Inconclusive
    } else if sequence_failed_at.is_some() {
        FixtureExpect::Fail
    } else {
        FixtureExpect::Pass
    };

    if observed == fixture.expect {
        SequenceFixtureOutcome::Match
    } else {
        let detail = sequence_failed_at
            .map(|(idx, msg)| format!("step {idx}: {msg}"))
            .or_else(|| {
                inconclusive_at.map(|idx| format!("precondition step {idx} returned isError"))
            })
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

    /// Regression: a crashed server used to be rewritten into an
    /// `isError: true` envelope, which satisfied `expect: error` and
    /// let the sequence pass.
    #[tokio::test]
    async fn crash_on_expect_error_step_fails_the_sequence() {
        use crate::client::CallOutcome;
        use crate::run::exec::MockClient;
        use rand::SeedableRng;
        let tool = |name: &str| {
            rmcp::model::Tool::new(
                name.to_string(),
                String::new(),
                std::sync::Arc::new(serde_json::Map::new()),
            )
        };
        let mut client = MockClient::new()
            .register(tool("record_delete"), |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            })
            .register(tool("record_read"), |_| {
                CallOutcome::Crash("process exited".to_string())
            });
        let sequence: Sequence = serde_yaml::from_str(
            "name: deleted_record_is_gone\nsteps:\n  - call: record_delete\n  - call: record_read\n    expect: error\n",
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut seen = std::collections::BTreeSet::new();
        let outcome = run_one_sequence(
            &mut client,
            &sequence,
            &mut rng,
            Duration::from_secs(1),
            None,
            0.0,
            &mut seen,
        )
        .await;
        match outcome {
            SequenceOutcome::Fail {
                step_index, detail, ..
            } => {
                assert_eq!(step_index, 1);
                assert!(detail.contains("crash: process exited"), "{detail}");
            }
            SequenceOutcome::Pass | SequenceOutcome::Inconclusive { .. } => {
                panic!("crashed step must fail the sequence")
            }
        }
    }

    /// A JSON-RPC error reply satisfies `expect: error`: reading a
    /// deleted record and getting "not found" is the correct behaviour.
    #[tokio::test]
    async fn json_rpc_error_satisfies_expect_error() {
        use crate::client::CallOutcome;
        use crate::run::exec::MockClient;
        use rand::SeedableRng;
        let tool = |name: &str| {
            rmcp::model::Tool::new(
                name.to_string(),
                String::new(),
                std::sync::Arc::new(serde_json::Map::new()),
            )
        };
        let mut client = MockClient::new()
            .register(tool("record_delete"), |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            })
            .register(tool("record_read"), |_| CallOutcome::JsonRpcError {
                code: -32602,
                message: "record not found".to_string(),
            });
        let sequence: Sequence = serde_yaml::from_str(
            "name: deleted_record_is_gone\nsteps:\n  - call: record_delete\n  - call: record_read\n    expect: error\n",
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut seen = std::collections::BTreeSet::new();
        let outcome = run_one_sequence(
            &mut client,
            &sequence,
            &mut rng,
            Duration::from_secs(1),
            None,
            0.0,
            &mut seen,
        )
        .await;
        assert!(matches!(outcome, SequenceOutcome::Pass));
    }

    fn crud_client(
        create: fn(&Value) -> crate::client::CallOutcome,
    ) -> crate::run::exec::MockClient {
        use crate::client::CallOutcome;
        let tool = |name: &str| {
            rmcp::model::Tool::new(
                name.to_string(),
                String::new(),
                std::sync::Arc::new(serde_json::Map::new()),
            )
        };
        crate::run::exec::MockClient::new()
            .register(tool("record_create"), create)
            .register(tool("record_delete"), |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            })
            .register(tool("record_read"), |_| {
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            })
    }

    async fn run_crud(client: &mut crate::run::exec::MockClient) -> SequenceOutcome {
        use rand::SeedableRng;
        let sequence: Sequence = serde_yaml::from_str(
            "name: s\nsteps:\n  - call: record_create\n    bind: created\n  - call: record_delete\n    with: { id: \"{{steps.created.response.structuredContent.id}}\" }\n  - call: record_read\n    with: { id: \"{{steps.created.response.structuredContent.id}}\" }\n    expect: error\n",
        )
        .unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let mut seen = std::collections::BTreeSet::new();
        run_one_sequence(
            client,
            &sequence,
            &mut rng,
            Duration::from_secs(1),
            None,
            0.0,
            &mut seen,
        )
        .await
    }

    /// Campaign regression: when the setup `create` rejected the probe's
    /// generic arguments, the sequence was reported as a state leak.
    #[tokio::test]
    async fn failed_precondition_step_is_inconclusive() {
        use crate::client::CallOutcome;
        let mut client =
            crud_client(|_| CallOutcome::Ok(rmcp::model::CallToolResult::error(vec![])));
        match run_crud(&mut client).await {
            SequenceOutcome::Inconclusive { step_index, .. } => assert_eq!(step_index, 0),
            SequenceOutcome::Pass => panic!("expected inconclusive, got pass"),
            SequenceOutcome::Fail { detail, .. } => {
                panic!("expected inconclusive, got fail: {detail}")
            }
        }
    }

    /// Setup succeeded but returned no `structuredContent.id`: the next
    /// step can't be built, which is not a state leak either.
    #[tokio::test]
    async fn unresolved_step_reference_is_inconclusive() {
        use crate::client::CallOutcome;
        let mut client =
            crud_client(|_| CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![])));
        match run_crud(&mut client).await {
            SequenceOutcome::Inconclusive { step_index, .. } => assert_eq!(step_index, 1),
            SequenceOutcome::Pass => panic!("expected inconclusive, got pass"),
            SequenceOutcome::Fail { detail, .. } => {
                panic!("expected inconclusive, got fail: {detail}")
            }
        }
    }

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
