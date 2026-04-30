use std::{fs, path::Path, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    run::{parse_invariants, PropertyPlan, Reporter},
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct PropertyArgs {
    /// Path to a YAML invariants file. Either `invariants` or `--pack`
    /// must be supplied.
    pub invariants: Option<PathBuf>,
    /// Name of a built-in rule pack (`auth`, `path-traversal`,
    /// `error-shape`). Resolved against `packs/` next to the
    /// `wallfacer.toml` (workspace root).
    #[arg(long)]
    pub pack: Option<String>,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long, default_value_t = 100)]
    pub cases: u32,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: PropertyArgs, config_path: Option<&Path>) -> Result<()> {
    let (config_file, config) =
        Config::load_from_lookup(config_path).context("failed to load config")?;
    let source = load_invariants_source(&args, &config_file)?;
    let file = parse_invariants(&source)?;

    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    let plan = PropertyPlan {
        file,
        default_cases: args.cases,
        master_seed: args.seed.unwrap_or_else(rand::random),
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
    };

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => Box::new(HumanReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
    };
    let report = plan
        .execute(&mut client, &corpus, reporter.as_mut())
        .await?;
    client.shutdown().await.ok();

    if report.findings_count == 0 {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// Resolves the YAML source for the run, honoring `--pack` when supplied.
///
/// `--pack <name>` looks under `<workspace>/packs/<name>.yaml` next to the
/// detected `wallfacer.toml`. We prefer that location so each project can
/// vendor its own packs without depending on a system-wide install.
fn load_invariants_source(args: &PropertyArgs, config_file: &Path) -> Result<String> {
    match (&args.invariants, &args.pack) {
        (Some(_), Some(_)) => {
            bail!("pass either an invariants file or `--pack <name>`, not both")
        }
        (None, None) => bail!("pass an invariants file or `--pack <name>`"),
        (Some(path), None) => fs::read_to_string(path)
            .with_context(|| format!("failed to read invariants file {}", path.display())),
        (None, Some(name)) => load_pack(config_file, name),
    }
}

fn load_pack(config_file: &Path, name: &str) -> Result<String> {
    if name.contains('/') || name.contains('\\') {
        bail!("`--pack <name>` must not contain path separators (got `{name}`)");
    }
    let workspace = config_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let candidates = [
        workspace.join("packs").join(format!("{name}.yaml")),
        workspace.join("packs").join(format!("{name}.yml")),
    ];
    for candidate in &candidates {
        if candidate.is_file() {
            return fs::read_to_string(candidate)
                .with_context(|| format!("failed to read pack {}", candidate.display()));
        }
    }
    bail!(
        "rule pack `{name}` not found; expected one of: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}
