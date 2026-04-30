//! CLI reporter implementations: human (table + progress bar), json (collect
//! and dump), and sarif (collect and dump SARIF 2.1.0).
//!
//! Reporters are owned by the CLI command. Each reporter receives lifecycle
//! callbacks from the plan and renders accordingly. Reporters never own the
//! plan and never make MCP calls themselves — they only translate plan
//! events into operator-facing output.

use std::io::IsTerminal;

use comfy_table::{presets::UTF8_FULL, Cell, Table};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use wallfacer_core::{
    finding::Finding,
    run::{Reporter, RunInfo},
    sarif,
};

/// Reporter that prints a progress bar to stderr and a final table of
/// findings + skipped tools to stdout.
pub struct HumanReporter {
    progress: Option<ProgressBar>,
    findings: Vec<Finding>,
    skipped: Vec<(String, String)>,
    blocked: Vec<String>,
    started: bool,
    /// `true` when stderr is a TTY; controls whether we render the progress
    /// bar at all (CI logs prefer plain "Found 3 findings" output).
    tty: bool,
}

impl HumanReporter {
    pub fn new() -> Self {
        Self {
            progress: None,
            findings: Vec::new(),
            skipped: Vec::new(),
            blocked: Vec::new(),
            started: false,
            tty: std::io::stderr().is_terminal(),
        }
    }
}

impl Default for HumanReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for HumanReporter {
    fn on_run_start(&mut self, info: &RunInfo) {
        self.started = true;
        self.blocked = info.blocked.clone();
        eprintln!(
            "Will run `{}` over {} tools across {} iterations (seed: {}); blocked: {:?}",
            info.kind,
            info.tools.len(),
            info.total_iterations,
            info.master_seed
                .map(|s| s.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            info.blocked,
        );
        if self.tty && info.total_iterations > 0 {
            let bar = ProgressBar::new(info.total_iterations);
            let style = ProgressStyle::with_template("{wide_bar} {pos}/{len} calls")
                .unwrap_or_else(|_| ProgressStyle::default_bar());
            bar.set_style(style);
            self.progress = Some(bar);
        }
    }

    fn on_iteration_end(&mut self, _tool: &str, _iteration: u64) {
        if let Some(progress) = &self.progress {
            progress.inc(1);
        }
    }

    fn on_finding(&mut self, finding: &Finding) {
        self.findings.push(finding.clone());
    }

    fn on_skipped(&mut self, tool: &str, reason: &str) {
        self.skipped.push((tool.to_string(), reason.to_string()));
    }

    fn on_run_end(&mut self) {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
        }
        let mut findings_table = Table::new();
        findings_table.load_preset(UTF8_FULL);
        findings_table.set_header(vec!["Tool", "Kind", "Severity", "Message"]);
        for finding in &self.findings {
            findings_table.add_row(vec![
                Cell::new(&finding.tool),
                Cell::new(format!("{:?}", finding.kind)),
                Cell::new(format!("{:?}", finding.severity)),
                Cell::new(&finding.message),
            ]);
        }
        println!("{findings_table}");
        if !self.skipped.is_empty() {
            let mut skipped_table = Table::new();
            skipped_table.load_preset(UTF8_FULL);
            skipped_table.set_header(vec!["Skipped tool", "Reason"]);
            for (tool, reason) in &self.skipped {
                skipped_table.add_row(vec![Cell::new(tool), Cell::new(reason)]);
            }
            eprintln!("\nSchema generation could not produce inputs for the following tools.");
            eprintln!("Use `--coverage-strict` in CI to fail when any tool is skipped.");
            eprintln!("{skipped_table}");
        }
    }
}

/// Reporter that collects every finding and skipped tool, then prints a JSON
/// document at run end.
pub struct JsonReporter {
    findings: Vec<Finding>,
    skipped: Vec<JsonSkipped>,
}

#[derive(Serialize)]
struct JsonSkipped {
    tool: String,
    reason: String,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    findings: &'a [Finding],
    #[serde(skip_serializing_if = "<[JsonSkipped]>::is_empty")]
    skipped: &'a [JsonSkipped],
}

impl JsonReporter {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            skipped: Vec::new(),
        }
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JsonReporter {
    fn on_finding(&mut self, finding: &Finding) {
        self.findings.push(finding.clone());
    }

    fn on_skipped(&mut self, tool: &str, reason: &str) {
        self.skipped.push(JsonSkipped {
            tool: tool.to_string(),
            reason: reason.to_string(),
        });
    }

    fn on_run_end(&mut self) {
        let report = JsonReport {
            findings: &self.findings,
            skipped: &self.skipped,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(body) => println!("{body}"),
            Err(error) => eprintln!("failed to render JSON report: {error}"),
        }
    }
}

/// Reporter that emits SARIF 2.1.0 at run end.
pub struct SarifReporter {
    findings: Vec<Finding>,
}

impl SarifReporter {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }
}

impl Default for SarifReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for SarifReporter {
    fn on_finding(&mut self, finding: &Finding) {
        self.findings.push(finding.clone());
    }

    fn on_run_end(&mut self) {
        let document = sarif::to_sarif(&self.findings, env!("CARGO_PKG_VERSION"));
        match serde_json::to_string_pretty(&document) {
            Ok(body) => println!("{body}"),
            Err(error) => eprintln!("failed to render SARIF report: {error}"),
        }
    }
}
