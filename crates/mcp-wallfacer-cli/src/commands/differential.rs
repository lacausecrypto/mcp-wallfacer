use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    differential::inferred_schema_dir,
    run::{DestructiveDetector, DifferentialPlan, Reporter},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct DifferentialArgs {
    #[arg(long)]
    pub learn: bool,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long, default_value_t = 20)]
    pub iterations: u64,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: DifferentialArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    let plan = DifferentialPlan {
        learn: args.learn,
        iterations: args.iterations,
        master_seed: args.seed.unwrap_or_else(rand::random),
        schema_dir: inferred_schema_dir(),
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
        detector: DestructiveDetector::from_config(&config.destructive, &config.allow_destructive)
            .context("invalid destructive / allowlist regex in config")?,
        severity: config.severity.clone(),
    };

    if plan.learn {
        let learned = plan.learn(&client).await?;
        client.shutdown().await.ok();
        println!("learned {learned} output schema baselines");
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
    Ok(())
}
