//! Live notifications emitted by plans during execution.
//!
//! Plans call into a [`Reporter`] at well-defined moments (run start,
//! per-iteration, on a finding, on a skip, run end) so front-ends can
//! render progress in any format — table, JSON stream, SARIF — without
//! the plan knowing or caring.
//!
//! All methods have empty default impls so a partial implementor only
//! handles what they need. [`NoopReporter`] is provided for tests that
//! don't care about output.

use crate::finding::Finding;

/// Identification for a given plan run, passed to [`Reporter::on_run_start`].
/// Consumers use this to render headers ("Will fuzz N tools across M
/// iterations").
#[derive(Debug, Clone)]
pub struct RunInfo {
    /// Short kind label (`"fuzz"`, `"differential"`, `"property"`, `"torture"`).
    pub kind: &'static str,
    /// Total number of (tool × iteration) units the plan intends to execute.
    pub total_iterations: u64,
    /// Tools the plan will exercise. May be empty for plans that don't fan
    /// out per-tool (e.g. `torture --mode state-leak`).
    pub tools: Vec<String>,
    /// Tools that were excluded before the run started. The
    /// [`String`] entries are typically tool names; the front-end is free to
    /// render them however it wants.
    pub blocked: Vec<String>,
    /// Master seed used to derive per-iteration seeds. `None` for plans
    /// that don't take a seed (e.g. `torture --mode state-leak`).
    pub master_seed: Option<u64>,
}

/// Notifications emitted by a [`crate::run`] plan as it executes.
///
/// Methods default to no-ops so implementations can opt into specific
/// hooks. The trait is `Send` so reporters can be moved across `await`
/// points alongside the plan.
pub trait Reporter: Send {
    /// Called once before any iteration runs.
    fn on_run_start(&mut self, _info: &RunInfo) {}

    /// Called before each (tool, iteration) call. `tool` may be empty for
    /// plans that don't iterate per tool.
    fn on_iteration_start(&mut self, _tool: &str, _iteration: u64) {}

    /// Called after each (tool, iteration) call, regardless of outcome.
    fn on_iteration_end(&mut self, _tool: &str, _iteration: u64) {}

    /// Called when a plan records a [`Finding`].
    fn on_finding(&mut self, _finding: &Finding) {}

    /// Called when a tool was skipped (e.g. unresolvable schema, marked
    /// destructive without explicit allowlist).
    fn on_skipped(&mut self, _tool: &str, _reason: &str) {}

    /// Called once after the run finishes, before the plan returns its
    /// report. The reporter may flush progress bars, write summary tables,
    /// etc.
    fn on_run_end(&mut self) {}
}

/// Reporter that ignores every callback. Useful in core unit tests.
#[derive(Debug, Default)]
pub struct NoopReporter;

impl Reporter for NoopReporter {}
