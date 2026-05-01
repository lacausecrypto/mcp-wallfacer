use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    mutate::GenMode,
    run::{DestructiveDetector, FuzzPlan, Reporter},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct FuzzArgs {
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long)]
    pub iterations: Option<u64>,
    #[arg(long, value_enum, default_value_t = FuzzMode::Mixed)]
    pub mode: FuzzMode,
    #[arg(long)]
    pub include: Vec<String>,
    #[arg(long)]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub max_tools: Option<usize>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Exit with status `2` when at least one tool was skipped because its
    /// schema could not be generated.
    #[arg(long)]
    pub coverage_strict: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FuzzMode {
    Conform,
    Adversarial,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl From<FuzzMode> for GenMode {
    fn from(value: FuzzMode) -> Self {
        match value {
            FuzzMode::Conform => GenMode::Conform,
            FuzzMode::Adversarial => GenMode::Adversarial,
            FuzzMode::Mixed => GenMode::Mixed,
        }
    }
}

pub async fn run(args: FuzzArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    let plan = FuzzPlan {
        iterations: args.iterations.unwrap_or(200),
        mode: args.mode.into(),
        master_seed: args.seed.unwrap_or_else(rand::random),
        include: args.include,
        exclude: args.exclude,
        max_tools: args.max_tools,
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
        detector: DestructiveDetector::from_config(&config.destructive, &config.allow_destructive)
            .context("invalid destructive / allowlist regex in config")?,
        severity: config.severity.clone(),
    };

    if args.dry_run {
        for name in plan.dry_run(&client).await? {
            println!("{name}");
        }
        client.shutdown().await.ok();
        return Ok(());
    }

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => Box::new(HumanReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
    };
    let report = plan
        .execute(&mut client, &corpus, reporter.as_mut())
        .await?;
    client.shutdown().await.ok();

    if report.findings_count > 0 {
        std::process::exit(1);
    }
    if args.coverage_strict && !report.skipped.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}
