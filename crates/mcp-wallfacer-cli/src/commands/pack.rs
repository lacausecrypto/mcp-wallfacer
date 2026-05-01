//! `wallfacer pack {list, show, init, test, params}` — Phase H pack
//! management commands.
//!
//! Lookup order across every subcommand: a pack named `<name>` is first
//! looked up at `<workspace>/packs/<name>.{yaml,yml}`; if absent there,
//! the embedded copy bundled at compile time wins. This means
//! workspace-vendored packs always shadow the built-ins of the same
//! name — `pack init` materialises the embedded source so a project can
//! customise it.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use wallfacer_core::{
    property::{
        dsl::{parse_with_overrides, synthesize_for_test, FixtureExpect, InvariantFile},
        runner::{evaluate_fixture, FixtureOutcome},
    },
    run::{
        embedded_pack_names, embedded_pack_source, evaluate_sequence_fixture,
        SequenceFixtureOutcome,
    },
    target::Config,
};

#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(subcommand)]
    pub command: PackCommand,
}

#[derive(Debug, Subcommand)]
pub enum PackCommand {
    /// List every pack known to wallfacer (workspace + embedded).
    List,
    /// Pretty-print a pack's invariants after templating.
    Show {
        /// Pack name. Workspace `packs/<name>.yaml` shadows the embedded
        /// copy of the same name.
        name: String,
        /// Override a parameter (`key=value`, repeatable).
        #[arg(long = "param", value_name = "KEY=VALUE")]
        param: Vec<String>,
    },
    /// Copy an embedded pack into the workspace `packs/` directory so
    /// it can be customised. Use `--force` to overwrite an existing file.
    Init {
        /// Pack name (must match an embedded pack).
        name: String,
        /// Overwrite an existing `packs/<name>.yaml`.
        #[arg(long)]
        force: bool,
    },
    /// Run inline `test_fixtures` declared on each invariant. Skips the
    /// MCP server entirely; pure local evaluation. Pass `--all` to run
    /// every pack's fixtures or a `name` to scope.
    Test {
        /// Pack name. Mutually exclusive with `--all`.
        name: Option<String>,
        /// Test every pack discovered in workspace + embedded.
        #[arg(long, conflicts_with = "name")]
        all: bool,
        /// Override a parameter applied to every loaded pack.
        #[arg(long = "param", value_name = "KEY=VALUE")]
        param: Vec<String>,
    },
    /// Show parameter declarations + currently-effective values for a
    /// pack (defaults overlaid by config and `--param`).
    Params {
        /// Pack name.
        name: String,
        /// Override a parameter (`key=value`, repeatable).
        #[arg(long = "param", value_name = "KEY=VALUE")]
        param: Vec<String>,
    },
}

pub async fn run(args: PackArgs, config_path: Option<&Path>) -> Result<()> {
    // Config is optional for `pack list` / `pack show` / `pack params`
    // because users routinely run them outside a configured workspace
    // (e.g. to discover the embedded packs). We still try to load it
    // so config-based overrides apply when present.
    let config = Config::load_from_lookup(config_path).ok();

    match args.command {
        PackCommand::List => list(config.as_ref()),
        PackCommand::Show { name, param } => show(&name, &param, config.as_ref()),
        PackCommand::Init { name, force } => init(&name, force, config.as_ref()),
        PackCommand::Test { name, all, param } => test(name, all, &param, config.as_ref()),
        PackCommand::Params { name, param } => params(&name, &param, config.as_ref()),
    }
}

fn workspace_root(config: Option<&(PathBuf, Config)>) -> PathBuf {
    config
        .and_then(|(path, _)| path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn parse_param_overrides(params: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for raw in params {
        let (key, value) = raw
            .split_once('=')
            .with_context(|| format!("invalid `--param`: expected `key=value`, got `{raw}`"))?;
        out.insert(key.trim().to_string(), value.to_string());
    }
    Ok(out)
}

/// Collects `[packs.<pack>]` overrides from the config, layered with
/// CLI `--param` values (CLI wins).
fn merged_overrides(
    pack_name: &str,
    cli_params: &[String],
    config: Option<&(PathBuf, Config)>,
) -> Result<BTreeMap<String, String>> {
    let mut overrides = BTreeMap::new();
    if let Some((_, config)) = config {
        if let Some(table) = config.packs.get(pack_name) {
            for (key, value) in table {
                overrides.insert(key.clone(), value.clone());
            }
        }
    }
    for (key, value) in parse_param_overrides(cli_params)? {
        overrides.insert(key, value);
    }
    Ok(overrides)
}

/// Sources where a pack's YAML can come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackSource {
    Workspace,
    Embedded,
}

impl PackSource {
    fn label(self) -> &'static str {
        match self {
            PackSource::Workspace => "workspace",
            PackSource::Embedded => "embedded",
        }
    }
}

/// Resolves `name` to a `(source, raw YAML)` pair. Workspace wins when
/// both layers carry the name.
fn resolve_pack(name: &str, workspace: &Path) -> Result<(PackSource, String)> {
    if name.contains('/') || name.contains('\\') {
        bail!("pack name must not contain path separators (got `{name}`)");
    }
    for ext in ["yaml", "yml"] {
        let candidate = workspace.join("packs").join(format!("{name}.{ext}"));
        if candidate.is_file() {
            let body = fs::read_to_string(&candidate)
                .with_context(|| format!("read {}", candidate.display()))?;
            return Ok((PackSource::Workspace, body));
        }
    }
    if let Some(source) = embedded_pack_source(name) {
        return Ok((PackSource::Embedded, source.to_string()));
    }
    bail!("rule pack `{name}` not found in workspace `packs/` or embedded library")
}

/// Enumerates every pack name discoverable in either layer (workspace +
/// embedded). Returns each name once, with its winning source.
fn enumerate_packs(workspace: &Path) -> Result<Vec<(String, PackSource)>> {
    let mut seen: BTreeMap<String, PackSource> = BTreeMap::new();
    // Embedded first (lower priority), then workspace overrides on top.
    for name in embedded_pack_names() {
        seen.insert(name.to_string(), PackSource::Embedded);
    }
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
                    seen.insert(stem.to_string(), PackSource::Workspace);
                }
            }
        }
    }
    Ok(seen.into_iter().collect())
}

// ---------- Subcommand implementations ----------

fn list(config: Option<&(PathBuf, Config)>) -> Result<()> {
    let workspace = workspace_root(config);
    let packs = enumerate_packs(&workspace)?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Name", "Source", "Description", "#"]);
    for (name, source) in packs {
        let (_, raw) = resolve_pack(&name, &workspace)?;
        // Parse with no overrides: `pack list` shouldn't fail because a
        // pack uses a parameter; we just want metadata + invariant count.
        match parse_with_overrides(&raw, &BTreeMap::new()) {
            Ok(file) => {
                let description = file
                    .metadata
                    .as_ref()
                    .and_then(|m| m.description.clone())
                    .unwrap_or_default();
                table.add_row(vec![
                    Cell::new(&name),
                    Cell::new(source.label()),
                    Cell::new(description),
                    Cell::new(file.invariants.len().to_string()),
                ]);
            }
            Err(err) => {
                table.add_row(vec![
                    Cell::new(&name),
                    Cell::new(source.label()),
                    Cell::new(format!("(parse error: {err})")).fg(Color::Red),
                    Cell::new("?"),
                ]);
            }
        }
    }
    println!("{table}");
    Ok(())
}

fn show(name: &str, params: &[String], config: Option<&(PathBuf, Config)>) -> Result<()> {
    let workspace = workspace_root(config);
    let (source_kind, raw) = resolve_pack(name, &workspace)?;
    let overrides = merged_overrides(name, params, config)?;
    let file = parse_with_overrides(&raw, &overrides).context("failed to parse pack")?;

    eprintln!("# pack: {name} ({})", source_kind.label());
    if let Some(metadata) = &file.metadata {
        if let Some(desc) = &metadata.description {
            eprintln!("# {desc}");
        }
        if !metadata.tags.is_empty() {
            eprintln!("# tags: {}", metadata.tags.join(", "));
        }
    }
    println!("{}", serde_yaml::to_string(&file)?);
    Ok(())
}

fn init(name: &str, force: bool, config: Option<&(PathBuf, Config)>) -> Result<()> {
    let Some(source) = embedded_pack_source(name) else {
        bail!(
            "no embedded pack named `{name}`; available: {}",
            embedded_pack_names().collect::<Vec<_>>().join(", ")
        );
    };
    let workspace = workspace_root(config);
    let packs_dir = workspace.join("packs");
    fs::create_dir_all(&packs_dir).with_context(|| format!("create {}", packs_dir.display()))?;
    let target = packs_dir.join(format!("{name}.yaml"));
    if target.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            target.display()
        );
    }
    fs::write(&target, source).with_context(|| format!("write {}", target.display()))?;
    println!("created {}", target.display());
    Ok(())
}

fn test(
    name: Option<String>,
    all: bool,
    params: &[String],
    config: Option<&(PathBuf, Config)>,
) -> Result<()> {
    let workspace = workspace_root(config);
    let names: Vec<String> = match (name, all) {
        (Some(n), false) => vec![n],
        (None, true) => enumerate_packs(&workspace)?
            .into_iter()
            .map(|(n, _)| n)
            .collect(),
        (None, false) => bail!("pass a pack name or `--all`"),
        (Some(_), true) => bail!("pass either a pack name or `--all`, not both"),
    };

    let mut total = 0usize;
    let mut matched = 0usize;
    let mut failures: Vec<TestFailure> = Vec::new();
    let mut empty_packs: Vec<String> = Vec::new();

    for pack_name in &names {
        let (_, raw) = resolve_pack(pack_name, &workspace)?;
        let overrides = merged_overrides(pack_name, params, config)?;
        let file = parse_with_overrides(&raw, &overrides)
            .with_context(|| format!("parse pack `{pack_name}`"))?;
        let pack_total = run_pack_fixtures(pack_name, &file, &mut matched, &mut failures);
        total += pack_total;
        if pack_total == 0 {
            empty_packs.push(pack_name.clone());
        }
    }

    print_test_summary(total, matched, &failures, &empty_packs);
    if !failures.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn run_pack_fixtures(
    pack_name: &str,
    file: &InvariantFile,
    matched: &mut usize,
    failures: &mut Vec<TestFailure>,
) -> usize {
    let mut total = 0usize;
    for invariant in &file.invariants {
        total += run_invariant_fixtures(pack_name, invariant, matched, failures);
    }
    // Phase I: also evaluate `apply.test_fixtures` of every for_each_tool
    // block. We synthesize a placeholder-tooled Invariant from each
    // block so `pack test` can validate the assertion logic without
    // contacting an MCP server. The placeholder is reflected in the
    // failure rows so authors see "(synth)" rather than a real tool.
    for block in &file.for_each_tool {
        let synth = match synthesize_for_test(block, "__pack_test__") {
            Ok(synth) => synth,
            Err(err) => {
                failures.push(TestFailure {
                    pack: pack_name.to_string(),
                    invariant: block.name.clone(),
                    fixture: "<synthesize>".to_string(),
                    expected: FixtureExpect::Pass,
                    observed: None,
                    detail: format!("(synthesize failed) {err}"),
                });
                continue;
            }
        };
        total += run_invariant_fixtures(pack_name, &synth, matched, failures);
    }
    // Phase L — every sequence's `test_fixtures` is evaluated against
    // its parent sequence using the canned per-step responses. The
    // failure reporter uses the sequence name in the "Invariant"
    // column so authors see which sequence broke.
    for sequence in &file.sequences {
        for fixture in &sequence.test_fixtures {
            total += 1;
            match evaluate_sequence_fixture(sequence, fixture) {
                SequenceFixtureOutcome::Match => *matched += 1,
                SequenceFixtureOutcome::Mismatch {
                    expected,
                    observed,
                    detail,
                } => failures.push(TestFailure {
                    pack: pack_name.to_string(),
                    invariant: sequence.name.clone(),
                    fixture: fixture.name.clone(),
                    expected,
                    observed: Some(observed),
                    detail,
                }),
                SequenceFixtureOutcome::Structural { error } => failures.push(TestFailure {
                    pack: pack_name.to_string(),
                    invariant: sequence.name.clone(),
                    fixture: fixture.name.clone(),
                    expected: fixture.expect,
                    observed: None,
                    detail: format!("(structural error) {error}"),
                }),
            }
        }
    }
    total
}

fn run_invariant_fixtures(
    pack_name: &str,
    invariant: &wallfacer_core::property::dsl::Invariant,
    matched: &mut usize,
    failures: &mut Vec<TestFailure>,
) -> usize {
    let mut total = 0usize;
    for fixture in &invariant.test_fixtures {
        total += 1;
        match evaluate_fixture(invariant, fixture) {
            FixtureOutcome::Match => *matched += 1,
            FixtureOutcome::Mismatch {
                expected,
                observed,
                detail,
            } => failures.push(TestFailure {
                pack: pack_name.to_string(),
                invariant: invariant.name.clone(),
                fixture: fixture.name.clone(),
                expected,
                observed: Some(observed),
                detail,
            }),
            FixtureOutcome::Structural { error } => failures.push(TestFailure {
                pack: pack_name.to_string(),
                invariant: invariant.name.clone(),
                fixture: fixture.name.clone(),
                expected: fixture.expect,
                observed: None,
                detail: format!("(structural error) {error}"),
            }),
        }
    }
    total
}

struct TestFailure {
    pack: String,
    invariant: String,
    fixture: String,
    expected: FixtureExpect,
    observed: Option<FixtureExpect>,
    detail: String,
}

fn print_test_summary(
    total: usize,
    matched: usize,
    failures: &[TestFailure],
    empty_packs: &[String],
) {
    let mut summary = Table::new();
    summary.load_preset(UTF8_FULL);
    summary.set_header(vec![
        "Pack",
        "Invariant",
        "Fixture",
        "Expected",
        "Observed",
        "Detail",
    ]);
    for failure in failures {
        let observed = failure
            .observed
            .map(|o| format!("{:?}", o).to_lowercase())
            .unwrap_or_else(|| "structural-error".to_string());
        summary.add_row(vec![
            Cell::new(&failure.pack),
            Cell::new(&failure.invariant),
            Cell::new(&failure.fixture),
            Cell::new(format!("{:?}", failure.expected).to_lowercase()).fg(Color::Yellow),
            Cell::new(observed).fg(Color::Red),
            Cell::new(&failure.detail),
        ]);
    }
    if !failures.is_empty() {
        println!("{summary}");
    }
    eprintln!(
        "pack test: {matched}/{total} fixtures match (failures: {})",
        failures.len()
    );
    if !empty_packs.is_empty() {
        eprintln!(
            "note: pack(s) with no test_fixtures (skipped): {}",
            empty_packs.join(", ")
        );
    }
}

fn params(name: &str, cli_params: &[String], config: Option<&(PathBuf, Config)>) -> Result<()> {
    let workspace = workspace_root(config);
    let (source_kind, raw) = resolve_pack(name, &workspace)?;
    // Parse with no overrides so we read the canonical defaults.
    let file = parse_with_overrides(&raw, &BTreeMap::new())?;
    let parameters = file.metadata.map(|m| m.parameters).unwrap_or_default();

    if parameters.is_empty() {
        eprintln!(
            "pack `{name}` ({}) declares no parameters",
            source_kind.label()
        );
        return Ok(());
    }

    let effective = merged_overrides(name, cli_params, config)?;
    let cli_set: BTreeSet<String> = parse_param_overrides(cli_params)?.into_keys().collect();
    let config_table: HashMap<String, String> = config
        .and_then(|(_, c)| c.packs.get(name).cloned())
        .unwrap_or_default()
        .into_iter()
        .collect();

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "Param",
        "Type",
        "Default",
        "Effective",
        "Source",
        "Description",
    ]);
    for (key, param) in &parameters {
        let default_str = serde_json::to_string(&param.default)?
            .trim_matches('"')
            .to_string();
        let effective_str = effective
            .get(key)
            .cloned()
            .unwrap_or_else(|| default_str.clone());
        let source = if cli_set.contains(key) {
            "cli"
        } else if config_table.contains_key(key) {
            "config"
        } else {
            "default"
        };
        table.add_row(vec![
            Cell::new(key),
            Cell::new(format!("{:?}", param.kind).to_lowercase()),
            Cell::new(default_str),
            Cell::new(effective_str),
            Cell::new(source),
            Cell::new(param.description.clone().unwrap_or_default()),
        ]);
    }
    println!("# pack: {name} ({})", source_kind.label());
    println!("{table}");
    Ok(())
}
