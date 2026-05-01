//! `wallfacer coverage` — pack/tool coverage matrix CLI command.
//!
//! Loads every pack the operator wants to consider (defaults to all
//! embedded packs), connects to the configured target, lists its
//! tools, and prints a `(tool, pack)` matrix with a per-cell
//! verdict. Identifies tools no pack would exercise (the
//! `Uncovered` bucket) and surfaces them as a `--strict` exit-code
//! gate for CI.
//!
//! The analysis is *static* — we don't actually run the packs;
//! we walk their declarations and the live `list_tools` output.
//! That makes the command instantaneous (single `list_tools` call)
//! and side-effect-free.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use wallfacer_core::{
    client::Client,
    coverage::{CoverageCell, CoverageMatrix},
    property::dsl::InvariantFile,
    run::{
        embedded_pack_names, resolve_pack, DestructiveDetector, EmbeddedLoader, LayeredLoader,
        PackLoader,
    },
    target::Config,
};

#[derive(Debug, Args)]
pub struct CoverageArgs {
    /// Pack(s) to include in the matrix. Repeatable. Defaults to
    /// every embedded pack when neither `--pack` nor `--pack-all`
    /// is set.
    #[arg(long)]
    pub pack: Vec<String>,
    /// Convenience flag — equivalent to passing every embedded
    /// pack via `--pack`.
    #[arg(long, conflicts_with = "pack")]
    pub pack_all: bool,
    /// Output format. Defaults to a Markdown-friendly terminal
    /// table; `json` is for scripting.
    #[arg(long, value_enum, default_value_t = CoverageFormat::Human)]
    pub format: CoverageFormat,
    /// Exit `2` when at least one tool falls into the `Uncovered`
    /// bucket (no pack would exercise it). Useful in CI to enforce
    /// an "every tool must be covered by at least one pack" policy.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CoverageFormat {
    Human,
    Json,
}

pub async fn run(args: CoverageArgs, config_path: Option<&Path>) -> Result<()> {
    let (config_file, config) =
        Config::load_from_lookup(config_path).context("failed to load config")?;
    let workspace = workspace_root(&config_file);

    let loader = LayeredLoader::new(
        WorkspacePackLoader {
            workspace: workspace.clone(),
        },
        EmbeddedLoader,
    );

    // Resolve the pack set: `--pack` overrides → `--pack-all` /
    // default → every embedded pack.
    let pack_names: Vec<String> = if !args.pack.is_empty() {
        args.pack.clone()
    } else {
        let mut names: Vec<String> = embedded_pack_names().map(|s| s.to_string()).collect();
        names.sort();
        names
    };

    // Load each pack into a fully-resolved [`InvariantFile`] (with
    // pack overrides from `[packs.<name>]` in wallfacer.toml).
    let mut packs: Vec<(String, InvariantFile)> = Vec::new();
    for name in &pack_names {
        let source = loader
            .load(name)
            .map_err(|err| anyhow::anyhow!("rule pack `{name}` not found: {err}"))?;
        let overrides = pack_overrides(&config, name);
        let file = resolve_pack(&source, &overrides, &loader)
            .with_context(|| format!("failed to resolve pack `{name}`"))?;
        packs.push((name.clone(), file));
    }

    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let tools = client
        .list_tools()
        .await
        .context("failed to list tools from MCP target")?;
    client.shutdown().await.ok();

    let detector = DestructiveDetector::from_config(&config.destructive, &config.allow_destructive)
        .context("invalid destructive / allowlist regex in config")?;

    let matrix = CoverageMatrix::build(&packs, &tools, &detector);

    match args.format {
        CoverageFormat::Human => print_human(&matrix),
        CoverageFormat::Json => println!("{}", serde_json::to_string_pretty(&matrix)?),
    }

    if args.strict && !matrix.uncovered_tools.is_empty() {
        eprintln!(
            "wallfacer coverage --strict: {} tool(s) uncovered: {:?}",
            matrix.uncovered_tools.len(),
            matrix.uncovered_tools
        );
        std::process::exit(2);
    }
    Ok(())
}

fn print_human(matrix: &CoverageMatrix) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    let mut header = vec!["Tool".to_string()];
    header.extend(matrix.packs.iter().cloned());
    table.set_header(header.iter().map(Cell::new));

    for tool in &matrix.tools {
        let mut row: Vec<Cell> = vec![Cell::new(tool)];
        for pack in &matrix.packs {
            let cell = matrix
                .cells
                .get(tool)
                .and_then(|row| row.get(pack))
                .copied()
                .unwrap_or(CoverageCell::Uncovered);
            row.push(match cell {
                CoverageCell::Covered => Cell::new("●").fg(Color::Green),
                CoverageCell::Blocked => Cell::new("⊘").fg(Color::Yellow),
                CoverageCell::Uncovered => Cell::new("·").fg(Color::DarkGrey),
            });
        }
        table.add_row(row);
    }
    println!("{table}");

    // Summary line.
    let covered = matrix.covered_cells();
    let total = matrix.total_cells();
    let pct = if total > 0 {
        (covered as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "\n{}/{} cells covered ({:.1}%) · {} tool(s) uncovered{}",
        covered,
        total,
        pct,
        matrix.uncovered_tools.len(),
        if matrix.uncovered_tools.is_empty() {
            String::new()
        } else {
            format!(": {:?}", matrix.uncovered_tools)
        }
    );
    println!("\nlegend:  ● covered    ⊘ blocked (destructive guard)    · uncovered");
}

fn workspace_root(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Walk `[packs.<name>]` in `wallfacer.toml` and return the
/// per-pack overrides. Mirrors the property command's
/// `build_overrides`, simplified to the minimum we need for
/// coverage analysis.
fn pack_overrides(config: &Config, pack_name: &str) -> BTreeMap<String, String> {
    config
        .packs
        .get(pack_name)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>()
}

/// `PackLoader` that reads `<workspace>/packs/<name>.{yaml,yml}`.
/// Mirrors the loader the property command uses, extracted here so
/// `coverage` doesn't depend on the property command's internals.
struct WorkspacePackLoader {
    workspace: PathBuf,
}

impl PackLoader for WorkspacePackLoader {
    fn load(&self, name: &str) -> std::result::Result<String, String> {
        for ext in ["yaml", "yml"] {
            let path = self.workspace.join("packs").join(format!("{name}.{ext}"));
            if path.is_file() {
                return fs::read_to_string(&path)
                    .map_err(|err| format!("read {}: {err}", path.display()));
            }
        }
        Err(format!(
            "no workspace pack named `{name}` under {}/packs",
            self.workspace.display()
        ))
    }
}

// Coverage logic itself is unit-tested in
// `wallfacer_core::coverage::tests`; this module's tests live in the
// e2e suite (`tests/e2e/coverage_reports_gaps.rs`).
