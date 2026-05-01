//! `wallfacer suggest` — pack auto-suggestion CLI command.
//!
//! Connects to the configured MCP target, lists its tools, runs
//! [`wallfacer_core::suggest::suggest_packs`] against the catalog,
//! and prints the recommendations in the requested format.
//!
//! Three output formats:
//! - `human` (default): Markdown-friendly table + a TOML snippet
//!   ready to paste into `wallfacer.toml`, plus the run command.
//! - `toml`: just the `[packs.<name>]` blocks, no surrounding
//!   prose. Useful for piping into a config update step.
//! - `json`: the raw [`PackSuggestion`] list — for scripting.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use wallfacer_core::{
    client::Client,
    suggest::{suggest_packs, PackSuggestion},
    target::Config,
};

#[derive(Debug, Args)]
pub struct SuggestArgs {
    /// Output format. `human` is the default and intended for the
    /// terminal; `toml` is meant to be appended to `wallfacer.toml`;
    /// `json` is for scripting.
    #[arg(long, value_enum, default_value_t = SuggestFormat::Human)]
    pub format: SuggestFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SuggestFormat {
    Human,
    Toml,
    Json,
}

pub async fn run(args: SuggestArgs, config_path: Option<&Path>) -> Result<()> {
    let (_, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let tools = client.list_tools().await.context("failed to list tools")?;
    client.shutdown().await.ok();

    let suggestions = suggest_packs(&tools);

    match args.format {
        SuggestFormat::Human => print_human(&suggestions),
        SuggestFormat::Toml => print_toml(&suggestions),
        SuggestFormat::Json => println!("{}", serde_json::to_string_pretty(&suggestions)?),
    }
    Ok(())
}

fn print_human(suggestions: &[PackSuggestion]) {
    if suggestions.is_empty() {
        println!(
            "no pack suggestions for this server (this is rare — file an issue if unexpected)"
        );
        return;
    }

    // Group by pack so the table reads pack-first.
    let mut by_pack: std::collections::BTreeMap<&str, Vec<&PackSuggestion>> =
        std::collections::BTreeMap::new();
    for s in suggestions {
        by_pack.entry(s.pack.as_str()).or_default().push(s);
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Pack", "Witness tool", "Reason"]);
    for group in by_pack.values() {
        for s in group {
            table.add_row(vec![
                Cell::new(&s.pack),
                Cell::new(s.witness_tool.as_deref().unwrap_or("(global)")),
                Cell::new(&s.reason),
            ]);
        }
    }
    println!("{table}");
    println!();

    // TOML snippet
    println!("# ---- merge into wallfacer.toml ----");
    print_toml(suggestions);
    println!();

    // Run command
    let unique_packs: Vec<&str> = by_pack.keys().copied().collect();
    if unique_packs.is_empty() {
        return;
    }
    let cmd_args: Vec<String> = unique_packs.iter().map(|p| format!("--pack {p}")).collect();
    println!("# ---- run all suggested packs ----");
    println!("wallfacer property {}", cmd_args.join(" "));
}

fn print_toml(suggestions: &[PackSuggestion]) {
    let mut by_pack: std::collections::BTreeMap<&str, Vec<&PackSuggestion>> =
        std::collections::BTreeMap::new();
    for s in suggestions {
        by_pack.entry(s.pack.as_str()).or_default().push(s);
    }
    for (pack, group) in &by_pack {
        // Pick the first suggestion per pack — overrides are
        // pack-scoped, not per-tool. Multiple witness candidates
        // mostly produce the same overrides; the first is fine.
        let s = match group.first() {
            Some(s) => s,
            None => continue,
        };
        if s.param_overrides.is_empty() {
            // Pack works with default parameters; we still print
            // an empty section so the operator knows this pack
            // applies (and can add custom overrides later).
            println!("[packs.{pack}]");
            println!("# default parameters are sufficient");
        } else {
            println!("[packs.{pack}]");
            for (k, v) in &s.param_overrides {
                println!("{k} = \"{v}\"");
            }
        }
        println!();
    }
}
