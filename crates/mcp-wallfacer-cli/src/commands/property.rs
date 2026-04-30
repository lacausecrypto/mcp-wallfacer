use std::{collections::BTreeMap, fs, path::Path, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    run::{resolve_pack, EmbeddedLoader, LayeredLoader, PackLoader, PropertyPlan, Reporter},
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
    /// Override a pack template parameter. Repeatable. Format `key=value`.
    /// Phase G: takes precedence over `[packs.<name>] key = "value"` from
    /// `wallfacer.toml`, which itself takes precedence over the pack's
    /// declared `default`.
    #[arg(long = "param", value_name = "KEY=VALUE")]
    pub param: Vec<String>,
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
    let workspace = workspace_root(&config_file);

    let primary_source = load_primary_source(&args, &workspace)?;
    let overrides = build_overrides(&args, &config)?;
    // Phase H: workspace `packs/` shadows embedded — same lookup order
    // as the new `wallfacer pack` commands.
    let loader = LayeredLoader::new(WorkspacePackLoader { workspace }, EmbeddedLoader);
    let file = resolve_pack(&primary_source, &overrides, &loader)
        .context("failed to resolve invariants / pack chain")?;

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

/// Returns the workspace directory where `packs/` lives. Falls back to
/// the current directory if the config file is at the repo root with no
/// parent (rare; the lookup walks up).
fn workspace_root(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Loads the primary invariants YAML source — either an explicit file
/// from `args.invariants`, or the workspace's `packs/<name>.yaml` when
/// `--pack <name>` was passed. Phase H — falls back to the embedded
/// pack library when the workspace lookup misses.
fn load_primary_source(args: &PropertyArgs, workspace: &Path) -> Result<String> {
    match (&args.invariants, &args.pack) {
        (Some(_), Some(_)) => {
            bail!("pass either an invariants file or `--pack <name>`, not both")
        }
        (None, None) => bail!("pass an invariants file or `--pack <name>`"),
        (Some(path), None) => fs::read_to_string(path)
            .with_context(|| format!("failed to read invariants file {}", path.display())),
        (None, Some(name)) => {
            let layered = LayeredLoader::new(
                WorkspacePackLoader {
                    workspace: workspace.to_path_buf(),
                },
                EmbeddedLoader,
            );
            layered
                .load(name)
                .map_err(|err| anyhow::anyhow!("rule pack `{name}` not found: {err}"))
        }
    }
}

fn load_pack_from_workspace(workspace: &Path, name: &str) -> Result<String> {
    if name.contains('/') || name.contains('\\') {
        bail!("`--pack <name>` must not contain path separators (got `{name}`)");
    }
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

/// Builds the parameter override map from (in increasing precedence):
///
/// 1. `[packs.<pack>]` table in `wallfacer.toml` (Phase G config).
/// 2. CLI `--param key=value` (repeatable).
fn build_overrides(args: &PropertyArgs, config: &Config) -> Result<BTreeMap<String, String>> {
    let mut overrides = BTreeMap::new();
    if let Some(pack_name) = &args.pack {
        if let Some(table) = config.packs.get(pack_name) {
            for (key, value) in table {
                overrides.insert(key.clone(), value.clone());
            }
        }
    }
    for raw in &args.param {
        let (key, value) = raw
            .split_once('=')
            .with_context(|| format!("invalid `--param`: expected `key=value`, got `{raw}`"))?;
        overrides.insert(key.trim().to_string(), value.to_string());
    }
    Ok(overrides)
}

/// `PackLoader` impl that reads `<workspace>/packs/<name>.{yaml,yml}`.
struct WorkspacePackLoader {
    workspace: PathBuf,
}

impl PackLoader for WorkspacePackLoader {
    fn load(&self, name: &str) -> std::result::Result<String, String> {
        load_pack_from_workspace(&self.workspace, name).map_err(|err| err.to_string())
    }
}
