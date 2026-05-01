use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    fuzz_corpus::FuzzCorpus,
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
    /// Phase R — enable the persistent fuzz corpus. Inputs that
    /// trigger findings or produce a previously-unseen response
    /// fingerprint are saved under
    /// `<corpus_dir>/../fuzz_corpus/<tool>/`. Subsequent runs read
    /// the corpus and mutate from it 90 % of the time. The
    /// remaining 10 % stays pure schema-driven random.
    #[arg(long)]
    pub corpus_feedback: bool,
    /// Override the corpus directory (defaults to a sibling of
    /// `[output] corpus_dir`).
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,
    /// Phase R — fraction of iterations that mutate from the
    /// corpus instead of generating a fresh schema-driven payload.
    /// Range `0.0..=1.0`. Default `0.9` matches AFL convention.
    #[arg(long, default_value_t = 0.9)]
    pub mutate_ratio: f64,
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

    // Phase R — enable the persistent fuzz corpus when requested.
    // Default location is `<corpus_dir>/../fuzz_corpus/`, sibling
    // to the findings corpus, so cleaning `.wallfacer/` clears
    // both atomically.
    let fuzz_corpus = if args.corpus_feedback {
        let dir = args.corpus_dir.clone().unwrap_or_else(|| {
            let findings_dir = PathBuf::from(&config.output.corpus_dir);
            findings_dir
                .parent()
                .map(|p| p.join("fuzz_corpus"))
                .unwrap_or_else(|| PathBuf::from(".wallfacer/fuzz_corpus"))
        });
        Some(FuzzCorpus::new(dir))
    } else {
        None
    };

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
        fuzz_corpus,
        mutate_ratio: args.mutate_ratio,
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
