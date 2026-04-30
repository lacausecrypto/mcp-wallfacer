use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use serde::Serialize;
use serde_json::json;
use wallfacer_core::{corpus::Corpus, finding::Finding};

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Baseline corpus directory (the "before" run).
    pub baseline: PathBuf,
    /// Candidate corpus directory (the "after" run, e.g. the PR branch).
    pub candidate: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Exit with status `1` when any regression is detected. Useful as a
    /// CI gate: fixes alone never fail the run.
    #[arg(long)]
    pub fail_on_regression: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct DiffReport<'a> {
    /// Findings present in the candidate but missing from the baseline.
    regressions: Vec<&'a Finding>,
    /// Findings present in the baseline but resolved in the candidate.
    fixes: Vec<&'a Finding>,
    /// Findings present in both corpora; reported for visibility, never
    /// counted as a regression.
    persisting: Vec<&'a Finding>,
}

pub async fn run(args: DiffArgs) -> Result<()> {
    let baseline = load_corpus(&args.baseline).context("failed to load baseline corpus")?;
    let candidate = load_corpus(&args.candidate).context("failed to load candidate corpus")?;
    let report = diff(&baseline, &candidate);
    print_report(&report, args.format)?;
    if args.fail_on_regression && !report.regressions.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn load_corpus(path: &Path) -> Result<Vec<Finding>> {
    let corpus = Corpus::new(path.to_path_buf());
    Ok(corpus.list_findings()?)
}

fn diff<'a>(baseline: &'a [Finding], candidate: &'a [Finding]) -> DiffReport<'a> {
    let baseline_index: BTreeMap<&str, &Finding> = baseline
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();
    let candidate_index: BTreeMap<&str, &Finding> = candidate
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect();

    let baseline_ids: BTreeSet<&str> = baseline_index.keys().copied().collect();
    let candidate_ids: BTreeSet<&str> = candidate_index.keys().copied().collect();

    let regressions = candidate_ids
        .difference(&baseline_ids)
        .filter_map(|id| candidate_index.get(id).copied())
        .collect();
    let fixes = baseline_ids
        .difference(&candidate_ids)
        .filter_map(|id| baseline_index.get(id).copied())
        .collect();
    let persisting = baseline_ids
        .intersection(&candidate_ids)
        .filter_map(|id| candidate_index.get(id).copied())
        .collect();

    DiffReport {
        regressions,
        fixes,
        persisting,
    }
}

fn print_report(report: &DiffReport<'_>, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            // Custom JSON encoding to keep the shape small and readable;
            // we don't expose the entire Finding repro here.
            let payload = json!({
                "regressions": render_section(&report.regressions),
                "fixes": render_section(&report.fixes),
                "persisting": render_section(&report.persisting),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Human => {
            print_section("Regressions", &report.regressions);
            print_section("Fixes", &report.fixes);
            print_section("Persisting", &report.persisting);
            eprintln!(
                "summary: {} regression(s), {} fix(es), {} persisting",
                report.regressions.len(),
                report.fixes.len(),
                report.persisting.len()
            );
        }
    }
    Ok(())
}

fn render_section(findings: &[&Finding]) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|finding| {
            json!({
                "id": finding.id,
                "tool": finding.tool,
                "kind": finding.kind,
                "severity": finding.severity,
                "message": finding.message,
            })
        })
        .collect()
}

fn print_section(title: &str, findings: &[&Finding]) {
    if findings.is_empty() {
        println!("{title}: none");
        return;
    }
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["ID", "Tool", "Kind", "Severity", "Message"]);
    for finding in findings {
        table.add_row(vec![
            Cell::new(&finding.id),
            Cell::new(&finding.tool),
            Cell::new(format!("{:?}", finding.kind)),
            Cell::new(format!("{:?}", finding.severity)),
            Cell::new(&finding.message),
        ]);
    }
    println!("{title}:");
    println!("{table}");
}
