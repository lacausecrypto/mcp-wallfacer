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
        embedded_pack_names, resolve_pack, DestructiveDetector, EmbeddedLoader, LayeredLoader,
        PackLoader, PropertyPlan, Reporter, SequencePlan,
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
    /// Phase V — enable the persistent fuzz corpus for the
    /// sequences in the loaded pack(s). Mirrors `wallfacer fuzz
    /// --corpus-feedback`: shares the corpus directory so a
    /// fuzz-discovered "interesting id" can seed a sequence's
    /// `create_tool` step on the next run.
    #[arg(long)]
    pub corpus_feedback: bool,
    /// Override the corpus directory (defaults to a sibling of
    /// `[output] corpus_dir`). Only consulted when
    /// `--corpus-feedback` is set.
    #[arg(long)]
    pub corpus_dir: Option<PathBuf>,
    /// Phase V — fraction of sequence-step inputs that mutate
    /// from the corpus instead of using the YAML literal.
    /// Range `0.0..=1.0`. Default `0.9` matches AFL convention
    /// and the v0.6 `fuzz` default.
    #[arg(long, default_value_t = 0.9)]
    pub mutate_ratio: f64,
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

    let master_seed = args.seed.unwrap_or_else(rand::random);
    // Split sequences out: PropertyPlan iterates invariants +
    // for_each_tool, SequencePlan iterates sequences. Both run on the
    // same corpus + reporter pair so findings stream into one place.
    let mut file = composition.file;
    let sequences = std::mem::take(&mut file.sequences);

    let plan = PropertyPlan {
        file,
        default_cases: args.cases,
        master_seed,
        timeout: Duration::from_millis(config.target.timeout_ms),
        transport_name: config.target.transport_name().to_string(),
        detector: DestructiveDetector::from_config(&config.destructive, &config.allow_destructive)
            .context("invalid destructive / allowlist regex in config")?,
        severity: config.severity.clone(),
        // Defer the reporter's `on_run_end` so any subsequent
        // sequence sub-run can stream its findings into the same
        // table before it gets printed.
        defer_run_end: !sequences.is_empty(),
    };

    let mut reporter: Box<dyn Reporter> = match args.format {
        OutputFormat::Human => {
            Box::new(HumanReporter::new().with_invariant_pack_index(composition.invariant_to_pack))
        }
        OutputFormat::Json => Box::new(JsonReporter::new()),
    };
    let prop_report = plan
        .execute(&mut client, &corpus, reporter.as_mut())
        .await?;

    // Sequences run on the same client (preserving any state the
    // single-tool invariants left behind) and accumulate into the
    // same reporter, so findings stream into a single output stream.
    let seq_report = if sequences.is_empty() {
        None
    } else {
        // Phase V — corpus integration mirrors the fuzz CLI: the
        // corpus dir defaults to a sibling of `[output] corpus_dir`
        // so sequence and fuzz cross-pollinate without extra
        // config.
        let fuzz_corpus = if args.corpus_feedback {
            let dir = args.corpus_dir.clone().unwrap_or_else(|| {
                let findings_dir = PathBuf::from(&config.output.corpus_dir);
                findings_dir
                    .parent()
                    .map(|p| p.join("fuzz_corpus"))
                    .unwrap_or_else(|| PathBuf::from(".wallfacer/fuzz_corpus"))
            });
            Some(wallfacer_core::fuzz_corpus::FuzzCorpus::new(dir))
        } else {
            None
        };
        let seq_plan = SequencePlan {
            sequences,
            master_seed,
            timeout: Duration::from_millis(config.target.timeout_ms),
            transport_name: config.target.transport_name().to_string(),
            severity: config.severity.clone(),
            fuzz_corpus,
            mutate_ratio: args.mutate_ratio,
        };
        let report = seq_plan
            .execute(&mut client, &corpus, reporter.as_mut())
            .await?;
        // Now that both sub-runs are done, flush the table.
        reporter.on_run_end();
        Some(report)
    };

    client.shutdown().await.ok();

    let total_findings =
        prop_report.findings_count + seq_report.as_ref().map(|r| r.findings_count).unwrap_or(0);
    if total_findings == 0 {
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
        sequences: Vec::new(),
    };
    let mut seen_invariants: BTreeSet<String> = BTreeSet::new();
    let mut seen_for_each: BTreeSet<String> = BTreeSet::new();
    let mut seen_sequences: BTreeSet<String> = BTreeSet::new();
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
        for sequence in file.sequences {
            // Sequences are deduped by canonical sequence name; first
            // pack wins, same as invariants.
            if seen_sequences.insert(sequence.name.clone()) {
                invariant_to_pack.insert(sequence.name.clone(), pack_name.clone());
                combined.sequences.push(sequence);
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
