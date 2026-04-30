use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use wallfacer_core::{
    client::Client,
    corpus::Corpus,
    property::dsl::InvariantFile,
    run::{
        embedded_pack_names, resolve_pack, EmbeddedLoader, LayeredLoader, PackLoader, PropertyPlan,
        Reporter,
    },
    target::Config,
};

use crate::reporters::{HumanReporter, JsonReporter};

#[derive(Debug, Args)]
pub struct PropertyArgs {
    /// Path to a YAML invariants file. Mutually exclusive with `--pack`
    /// / `--pack-all`.
    pub invariants: Option<PathBuf>,
    /// One or more rule-pack names. Repeatable. Each pack is loaded
    /// (workspace `packs/` shadows embedded), templated with overrides,
    /// and its invariants are concatenated with deduplication by
    /// canonical name. Phase J.
    #[arg(long)]
    pub pack: Vec<String>,
    /// Convenience flag equivalent to passing `--pack <every-embedded-pack>`.
    /// Mutually exclusive with `--pack`. Phase J.
    #[arg(long, conflicts_with = "pack")]
    pub pack_all: bool,
    /// Override a pack template parameter. Repeatable. Format `key=value`.
    /// CLI overrides shadow `[packs.<name>] key = "value"` in
    /// `wallfacer.toml`, which itself shadows the pack's declared
    /// `default`.
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
    let loader = LayeredLoader::new(
        WorkspacePackLoader {
            workspace: workspace.clone(),
        },
        EmbeddedLoader,
    );

    let composition = compose_invariants(&args, &config, &workspace, &loader)?;

    let corpus = Corpus::from_config(&config.output);
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    let plan = PropertyPlan {
        file: composition.file,
        default_cases: args.cases,
        master_seed: args.seed.unwrap_or_else(rand::random),
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
    };

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => {
            Box::new(HumanReporter::new().with_invariant_pack_index(composition.invariant_to_pack))
        }
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

/// Composition result: a flattened [`InvariantFile`] plus a side-map
/// from invariant name to source pack name (for grouped reporting).
struct Composition {
    file: InvariantFile,
    invariant_to_pack: BTreeMap<String, String>,
}

fn compose_invariants(
    args: &PropertyArgs,
    config: &Config,
    workspace: &Path,
    loader: &dyn PackLoader,
) -> Result<Composition> {
    // Mutually-exclusive flag set: either an explicit `invariants`
    // file, or one-or-more `--pack` names, or `--pack-all`.
    if args.invariants.is_some() && (!args.pack.is_empty() || args.pack_all) {
        bail!("pass either an invariants file or `--pack` / `--pack-all`, not both");
    }
    if args.invariants.is_none() && args.pack.is_empty() && !args.pack_all {
        bail!("pass an invariants file, one or more `--pack <name>`, or `--pack-all`");
    }

    if let Some(path) = &args.invariants {
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read invariants file {}", path.display()))?;
        let overrides = build_overrides(args, config, None);
        let file =
            resolve_pack(&source, &overrides, loader).context("failed to parse invariants")?;
        return Ok(Composition {
            file,
            invariant_to_pack: BTreeMap::new(),
        });
    }

    // Discover the requested pack names and load each one. `--pack-all`
    // expands to every embedded pack, in alphabetical order.
    let pack_names: Vec<String> = if args.pack_all {
        let mut names: Vec<String> = embedded_pack_names().map(|s| s.to_string()).collect();
        // Add workspace-only packs (not shadowing embedded; we'd already
        // get those by name).
        let packs_dir = workspace.join("packs");
        if packs_dir.is_dir() {
            for entry in fs::read_dir(&packs_dir)
                .with_context(|| format!("read {}", packs_dir.display()))?
                .flatten()
            {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
                {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if !names.iter().any(|n| n == stem) {
                            names.push(stem.to_string());
                        }
                    }
                }
            }
        }
        names.sort();
        names
    } else {
        args.pack.clone()
    };

    let mut combined = InvariantFile {
        version: 3,
        metadata: None,
        invariants: Vec::new(),
        for_each_tool: Vec::new(),
    };
    let mut seen_invariants: BTreeSet<String> = BTreeSet::new();
    let mut seen_for_each: BTreeSet<String> = BTreeSet::new();
    let mut invariant_to_pack: BTreeMap<String, String> = BTreeMap::new();

    for pack_name in &pack_names {
        let source = loader
            .load(pack_name)
            .map_err(|err| anyhow::anyhow!("rule pack `{pack_name}` not found: {err}"))?;
        let overrides = build_overrides(args, config, Some(pack_name));
        let file = resolve_pack(&source, &overrides, loader)
            .with_context(|| format!("failed to resolve pack `{pack_name}`"))?;

        for invariant in file.invariants {
            // Dedup by canonical name. The first pack to declare the
            // name wins; subsequent duplicates are silently skipped so
            // operators can layer packs without worrying about the
            // load order.
            if seen_invariants.insert(invariant.name.clone()) {
                invariant_to_pack.insert(invariant.name.clone(), pack_name.clone());
                combined.invariants.push(invariant);
            }
        }
        for block in file.for_each_tool {
            // for_each_tool blocks are deduped by template name (the
            // expanded `{{tool_name}}` placeholder is identical across
            // duplicates by construction).
            if seen_for_each.insert(block.name.clone()) {
                combined.for_each_tool.push(block);
            }
        }
    }

    Ok(Composition {
        file: combined,
        invariant_to_pack,
    })
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

/// Builds the parameter override map. CLI `--param` flags shadow any
/// `[packs.<pack>]` table in the config. When `pack_name` is `None`
/// (raw invariants file), only the CLI flags apply.
fn build_overrides(
    args: &PropertyArgs,
    config: &Config,
    pack_name: Option<&str>,
) -> BTreeMap<String, String> {
    let mut overrides = BTreeMap::new();
    if let Some(name) = pack_name {
        if let Some(table) = config.packs.get(name) {
            for (key, value) in table {
                overrides.insert(key.clone(), value.clone());
            }
        }
    }
    for raw in &args.param {
        if let Some((key, value)) = raw.split_once('=') {
            overrides.insert(key.trim().to_string(), value.to_string());
        }
    }
    overrides
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
