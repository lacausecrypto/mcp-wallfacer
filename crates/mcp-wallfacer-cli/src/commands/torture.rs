use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    run::{parse_duration, Reporter, TortureMode, TortureRun},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct TortureArgs {
    #[arg(long, value_enum, default_value_t = TortureModeArg::Parallel)]
    pub mode: TortureModeArg,
    #[arg(long)]
    pub target_tool: Option<String>,
    #[arg(long, default_value_t = 50)]
    pub concurrency: usize,
    #[arg(long, default_value = "30s")]
    pub duration: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TortureModeArg {
    Parallel,
    StateLeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl From<TortureModeArg> for TortureMode {
    fn from(value: TortureModeArg) -> Self {
        match value {
            TortureModeArg::Parallel => TortureMode::Parallel,
            TortureModeArg::StateLeak => TortureMode::StateLeak,
        }
    }
}

pub async fn run(args: TortureArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let timeout = parse_duration(&args.duration).unwrap_or_else(|| Duration::from_secs(30));

    let run = TortureRun::new(
        args.mode.into(),
        args.target_tool
            .unwrap_or_else(|| "counter_inc".to_string()),
        args.concurrency,
        timeout,
        config.target.transport_name().to_string(),
    );

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => Box::new(HumanReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
    };
    let report = run.execute(&client, &corpus, reporter.as_mut()).await?;
    client.shutdown().await.ok();

    if report.findings_count == 0 {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
