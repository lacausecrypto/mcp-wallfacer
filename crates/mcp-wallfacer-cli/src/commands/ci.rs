use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    differential::inferred_schema_dir,
    finding::Severity,
    run::{DifferentialPlan, DifferentialReport, Reporter},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter, SarifReporter};

#[derive(Debug, Args)]
pub struct CiArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    #[arg(long, value_enum, default_value_t = SeverityThreshold::Medium)]
    pub severity_threshold: SeverityThreshold,
    #[arg(long, default_value = "10m")]
    pub max_duration: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityThreshold> for Severity {
    fn from(value: SeverityThreshold) -> Self {
        match value {
            SeverityThreshold::Low => Severity::Low,
            SeverityThreshold::Medium => Severity::Medium,
            SeverityThreshold::High => Severity::High,
            SeverityThreshold::Critical => Severity::Critical,
        }
    }
}

pub async fn run(args: CiArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    // CI runs a single boundary-payload differential pass: it's the cheapest
    // and most deterministic check, suitable for branch protection rules.
    let plan = DifferentialPlan {
        learn: false,
        iterations: 1,
        master_seed: 0,
        schema_dir: inferred_schema_dir(),
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
    };

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => Box::new(HumanReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
        OutputFormat::Sarif => Box::new(SarifReporter::new()),
    };
    let report: DifferentialReport = plan
        .execute(&mut client, &corpus, reporter.as_mut())
        .await?;
    client.shutdown().await.ok();

    let threshold: Severity = args.severity_threshold.into();
    if report
        .max_severity
        .is_some_and(|severity| severity >= threshold)
    {
        std::process::exit(1);
    }
    Ok(())
}
