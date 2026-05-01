//! `wallfacer report` — static HTML / JSON dashboard for a corpus.
//!
//! Reads `.wallfacer/corpus/` (or any directory passed via
//! `--corpus`), lists every persisted finding, and writes a
//! self-contained dashboard to disk. The HTML output has no
//! external assets (no JS, no remote CSS) — open the file in any
//! browser, anywhere, no internet required.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    corpus::Corpus,
    report::{render_html, ReportInputs},
    target::{default_corpus_dir, Config},
};

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Output format. Defaults to `html`.
    #[arg(long, value_enum, default_value_t = ReportFormat::Html)]
    pub format: ReportFormat,
    /// Directory to read findings from. Defaults to
    /// `[output] corpus_dir` from `wallfacer.toml`, or
    /// `.wallfacer/corpus` when no config is found.
    #[arg(long)]
    pub corpus: Option<PathBuf>,
    /// Output file path. Defaults to `wallfacer-report.html` (or
    /// `.json`) in the current directory. Pass `-` for stdout.
    #[arg(long, short = 'o')]
    pub out: Option<String>,
    /// Optional title surfaced in the report header.
    #[arg(long)]
    pub title: Option<String>,
    /// Optional target identifier (URL, package name) surfaced in
    /// the report header. Defaults to the `[target]` block of the
    /// config when readable.
    #[arg(long)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Html,
    Json,
}

pub async fn run(args: ReportArgs, config_path: Option<&Path>) -> Result<()> {
    // Locate the corpus dir. CLI flag wins; otherwise fall back to
    // the loaded config; otherwise the conventional default.
    let config: Option<Config> = Config::load_from_lookup(config_path).ok().map(|(_, c)| c);
    let corpus_dir = args
        .corpus
        .clone()
        .or_else(|| config.as_ref().map(|c| PathBuf::from(&c.output.corpus_dir)))
        .unwrap_or_else(default_corpus_dir);

    let corpus = Corpus::new(corpus_dir.clone());
    let findings = corpus
        .list_findings()
        .with_context(|| format!("read findings from {}", corpus_dir.display()))?;

    let target = args.target.clone().or_else(|| {
        config.as_ref().map(|c| {
            format!(
                "{} ({})",
                c.target.transport_name(),
                summarise_target(&c.target)
            )
        })
    });

    let body = match args.format {
        ReportFormat::Html => render_html(&ReportInputs {
            findings: &findings,
            coverage: None,
            title: args.title.as_deref(),
            target: target.as_deref(),
        }),
        ReportFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "title": args.title,
            "target": target,
            "findings_count": findings.len(),
            "findings": findings,
        }))?,
    };

    let out_path = match args.out.as_deref() {
        Some("-") => None,
        Some(path) => Some(PathBuf::from(path)),
        None => Some(PathBuf::from(match args.format {
            ReportFormat::Html => "wallfacer-report.html",
            ReportFormat::Json => "wallfacer-report.json",
        })),
    };

    if let Some(path) = out_path {
        fs::write(&path, &body).with_context(|| format!("write {}", path.display()))?;
        eprintln!(
            "wrote {} ({} finding{}) to {}",
            match args.format {
                ReportFormat::Html => "HTML report",
                ReportFormat::Json => "JSON report",
            },
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            path.display()
        );
    } else {
        print!("{body}");
    }
    Ok(())
}

fn summarise_target(target: &wallfacer_core::target::Target) -> String {
    match &target.transport {
        wallfacer_core::target::Transport::Stdio { command, .. } => command.clone(),
        wallfacer_core::target::Transport::Http { url, .. } => url.clone(),
    }
}
