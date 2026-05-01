use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    run::{parse_duration, DestructiveDetector, Reporter, TortureMode, TortureRun},
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
    /// Per-call timeout (e.g. `5s`, `500ms`). Each fan-out task is
    /// individually capped at this value.
    #[arg(long, default_value = "30s")]
    pub per_call_timeout: String,
    /// Global deadline for the whole torture run (e.g. `2m`). Defaults
    /// to `4 × per_call_timeout`. When the deadline elapses, every
    /// in-flight task is cancelled.
    #[arg(long)]
    pub global_deadline: Option<String>,
    /// Deprecated alias for `--per-call-timeout`. Older runbooks pass
    /// `--duration` and used to silently get a per-call cap; the name
    /// suggested an overall budget. Keep accepting it but warn.
    #[arg(long, hide = true)]
    pub duration: Option<String>,
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

    // Older invocations passed `--duration` thinking it was a global
    // cap; treat it as the per-call timeout when present (matches the
    // historical behaviour) and emit a friendly nudge.
    let per_call_source = if let Some(legacy) = args.duration.as_deref() {
        eprintln!(
            "warning: --duration is deprecated; pass --per-call-timeout for the per-call cap \
             and --global-deadline for the overall budget."
        );
        legacy
    } else {
        args.per_call_timeout.as_str()
    };
    let timeout = parse_duration(per_call_source).unwrap_or_else(|| Duration::from_secs(30));

    let detector = DestructiveDetector::from_config(&config.destructive, &config.allow_destructive)
        .context("invalid destructive / allowlist regex in config")?;
    let mut run = TortureRun::new(
        args.mode.into(),
        args.target_tool
            .unwrap_or_else(|| "counter_inc".to_string()),
        args.concurrency,
        timeout,
        config.target.transport_name().to_string(),
        detector,
    )
    .with_severity(config.severity.clone());
    if let Some(deadline) = args.global_deadline.as_deref() {
        if let Some(parsed) = parse_duration(deadline) {
            run.global_deadline = parsed;
        } else {
            eprintln!(
                "warning: could not parse --global-deadline `{deadline}`; using default \
                 (4 × per-call timeout)"
            );
        }
    }

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
