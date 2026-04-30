//! Torture run: parallel calls + state-leak probing.
//!
//! Phase E2 wraps every parallel call in a [`CancellationToken`]-aware
//! `select!` so a global deadline can abort hung tasks without blocking
//! the rest of the run.

use std::time::Duration;

use anyhow::Result;
use futures::future::join_all;
use serde::Serialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::{
    client::CallOutcome,
    corpus::Corpus,
    differential::response_value,
    finding::{Finding, FindingKind, ReproInfo},
};

use super::{
    exec::McpExec,
    reporter::{Reporter, RunInfo},
};

/// Outcome of a torture run.
///
/// Phase E4: the report carries only a count; the actual `Finding`
/// objects are streamed via the [`Reporter::on_finding`] callback.
#[derive(Debug, Default, Serialize)]
pub struct TortureReport {
    /// Number of concurrency / state-leak findings produced.
    pub findings_count: usize,
}

/// Torture mode: which kind of probing to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TortureMode {
    /// Fan out N parallel calls and verify they all complete (and that any
    /// shared counter state is updated atomically).
    Parallel,
    /// Probe whether session-scoped data leaks between callers.
    StateLeak,
}

/// Default ratio between per-call timeout and global deadline. The global
/// deadline must be at least this many times the per-call timeout so each
/// task gets a chance to complete naturally before cancellation kicks in.
pub const GLOBAL_DEADLINE_FACTOR: u32 = 4;

/// Torture plan.
pub struct TortureRun {
    /// Mode to execute.
    pub mode: TortureMode,
    /// Tool name to fan out against (parallel mode). Defaults to
    /// `counter_inc` matching the Phase A fixture.
    pub target_tool: String,
    /// Number of parallel calls in `Parallel` mode.
    pub concurrency: usize,
    /// Per-call timeout.
    pub timeout: Duration,
    /// Global deadline. When elapsed, every still-running task is
    /// cancelled. Defaults to [`GLOBAL_DEADLINE_FACTOR`] × `timeout` if
    /// left at the default.
    pub global_deadline: Duration,
    /// Transport label for `ReproInfo`.
    pub transport_name: String,
}

impl TortureRun {
    /// Convenience: builds a run with a sensible global deadline.
    #[must_use]
    pub fn new(
        mode: TortureMode,
        target_tool: String,
        concurrency: usize,
        timeout: Duration,
        transport_name: String,
    ) -> Self {
        Self {
            mode,
            target_tool,
            concurrency,
            timeout,
            global_deadline: timeout
                .checked_mul(GLOBAL_DEADLINE_FACTOR)
                .unwrap_or(timeout),
            transport_name,
        }
    }

    /// Drives the torture loop.
    pub async fn execute<C: McpExec + ?Sized>(
        self,
        client: &C,
        corpus: &Corpus,
        reporter: &mut dyn Reporter,
    ) -> Result<TortureReport> {
        reporter.on_run_start(&RunInfo {
            kind: "torture",
            total_iterations: self.concurrency as u64,
            tools: vec![self.target_tool.clone()],
            blocked: Vec::new(),
            master_seed: None,
        });

        let token = CancellationToken::new();
        // Global deadline watchdog: fires the cancel token if the run
        // overruns, so hung tasks don't block the join below forever.
        // The watchdog also exits early when the token is cancelled by
        // the main loop (work finished cleanly), so we don't pay the full
        // deadline at the end of every successful run.
        let watchdog = {
            let token = token.clone();
            let deadline = self.global_deadline;
            tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep(deadline) => {
                        token.cancel();
                    }
                    () = token.cancelled() => {
                        // Main work finished; exit cleanly.
                    }
                }
            })
        };

        let findings = match self.mode {
            TortureMode::Parallel => self.run_parallel(client, &token).await,
            TortureMode::StateLeak => self.run_state_leak(client).await,
        };

        // We are done with the work; cancel the watchdog so it doesn't
        // outlive us if it hasn't fired yet.
        token.cancel();
        let _ = watchdog.await;

        let mut report = TortureReport::default();
        for finding in findings {
            corpus.write_finding(&finding)?;
            reporter.on_finding(&finding);
            report.findings_count += 1;
        }
        reporter.on_run_end();
        Ok(report)
    }

    async fn run_parallel<C: McpExec + ?Sized>(
        &self,
        client: &C,
        token: &CancellationToken,
    ) -> Vec<Finding> {
        let payload = json!({});
        let calls = (0..self.concurrency)
            .map(|_| {
                guarded_call(
                    client,
                    &self.target_tool,
                    payload.clone(),
                    self.timeout,
                    token,
                )
            })
            .collect::<Vec<_>>();
        let outcomes = join_all(calls).await;
        let success_count = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CallOutcome::Ok(_)))
            .count();

        let mut findings = Vec::new();
        if success_count < self.concurrency {
            findings.push(Finding::new(
                FindingKind::ProtocolError,
                self.target_tool.clone(),
                "parallel calls did not all complete successfully",
                format!("{success_count}/{} calls completed", self.concurrency),
                ReproInfo {
                    seed: 0,
                    tool_call: payload.clone(),
                    transport: self.transport_name.clone(),
                    composition_trail: Vec::new(),
                },
            ));
        }

        // Counter atomicity probe: only meaningful for the canonical fixture.
        if self.target_tool == "counter_inc" {
            let counter =
                match guarded_call(client, "counter_get", json!({}), self.timeout, token).await {
                    CallOutcome::Ok(result) => response_value(&result)
                        .get("counter")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize,
                    _ => 0,
                };
            if counter != self.concurrency {
                findings.push(Finding::new(
                    FindingKind::PropertyFailure {
                        invariant: "counter_inc must be atomic".to_string(),
                    },
                    self.target_tool.clone(),
                    "counter lost updates under parallel calls",
                    format!("expected counter {}, observed {counter}", self.concurrency),
                    ReproInfo {
                        seed: 0,
                        tool_call: payload,
                        transport: self.transport_name.clone(),
                        composition_trail: Vec::new(),
                    },
                ));
            }
        }
        findings
    }

    async fn run_state_leak<C: McpExec + ?Sized>(&self, client: &C) -> Vec<Finding> {
        let set_payload = json!({"key": "secret", "value": "alice-data"});
        let get_payload = json!({"key": "secret"});
        let _ = client
            .call_tool("session_set", set_payload, self.timeout)
            .await;
        let observed = match client
            .call_tool("session_get", get_payload.clone(), self.timeout)
            .await
        {
            CallOutcome::Ok(result) => response_value(&result),
            other => json!({"unexpected": format!("{other:?}")}),
        };
        let leaked = observed.get("value").is_some_and(|value| !value.is_null());
        if !leaked {
            return Vec::new();
        }
        vec![Finding::new(
            FindingKind::StateLeak,
            "session_get",
            "session data is visible outside its expected boundary",
            format!(
                "observed response: {}",
                serde_json::to_string_pretty(&observed).unwrap_or_default()
            ),
            ReproInfo {
                seed: 0,
                tool_call: get_payload,
                transport: self.transport_name.clone(),
                composition_trail: Vec::new(),
            },
        )]
    }
}

/// Wraps a `call_tool` future in a cancellation-aware `select!`. When the
/// token is fired, the future is dropped and a synthetic
/// [`CallOutcome::Hang`] is returned so the caller can record a finding.
async fn guarded_call<C: McpExec + ?Sized>(
    client: &C,
    tool: &str,
    args: Value,
    timeout: Duration,
    token: &CancellationToken,
) -> CallOutcome {
    if token.is_cancelled() {
        return CallOutcome::Hang(timeout);
    }
    tokio::select! {
        outcome = client.call_tool(tool, args, timeout) => outcome,
        _ = token.cancelled() => CallOutcome::Hang(timeout),
    }
}

/// Parses a `30s`/`500ms`/`5` duration string. Plain integers are seconds.
///
/// Suffix order matters: `ms` must be checked before `s`, otherwise the
/// `s` suffix strips successfully and leaves a non-numeric `m` behind.
pub fn parse_duration(value: &str) -> Option<Duration> {
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds.parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(seconds) = value.strip_suffix('s') {
        return seconds.parse::<u64>().ok().map(Duration::from_secs);
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_handles_units() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("5"), Some(Duration::from_secs(5)));
        assert_eq!(parse_duration("nope"), None);
    }
}
