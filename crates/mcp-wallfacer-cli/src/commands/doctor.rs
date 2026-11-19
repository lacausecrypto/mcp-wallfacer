use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use wallfacer_core::{client::Client, target::Config};

#[derive(Debug, Args)]
pub struct DoctorArgs {}

pub async fn run(_args: DoctorArgs, config_path: Option<&Path>) -> Result<()> {
    let (path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;

    let tools = client.list_tools().await.context("failed to list tools")?;
    // Capability-aware listing: "n/a" when the server didn't declare the
    // capability, a count when the listing works, and "error" when the
    // server declares the capability but the listing fails (seen in the
    // wild as `-32601 Method not found`). The latter is a server-side
    // inconsistency worth reporting, not a reason to abort: tools were
    // listed, so the target is usable.
    let capabilities = client.server_capabilities().await;
    let resources = if capabilities.as_ref().is_some_and(|c| c.resources.is_some()) {
        Listing::from(client.list_resources().await.map(|r| r.len()))
    } else {
        Listing::NotDeclared
    };
    let prompts = if capabilities.as_ref().is_some_and(|c| c.prompts.is_some()) {
        Listing::from(client.list_prompts().await.map(|p| p.len()))
    } else {
        Listing::NotDeclared
    };
    for (capability, method, listing) in [
        ("resources", "resources/list", &resources),
        ("prompts", "prompts/list", &prompts),
    ] {
        if let Listing::Failed(error) = listing {
            eprintln!(
                "warning: server declares the `{capability}` capability but `{method}` failed: {error}"
            );
        }
    }

    let mut summary = Table::new();
    summary.load_preset(UTF8_FULL);
    summary.set_header(vec!["Config", "Transport", "Tools", "Resources", "Prompts"]);
    summary.add_row(vec![
        Cell::new(path.display()),
        Cell::new(config.target.transport_name()),
        Cell::new(tools.len()),
        Cell::new(resources.cell()),
        Cell::new(prompts.cell()),
    ]);
    println!("{summary}");

    let mut tools_table = Table::new();
    tools_table.load_preset(UTF8_FULL);
    tools_table.set_header(vec!["Tool", "Description"]);
    for tool in tools {
        tools_table.add_row(vec![
            Cell::new(tool.name.as_ref()),
            Cell::new(tool.description.as_deref().unwrap_or("")),
        ]);
    }
    println!("{tools_table}");

    client
        .shutdown()
        .await
        .context("failed to shut down client")?;
    Ok(())
}

/// Outcome of an optional capability listing (`resources/list`,
/// `prompts/list`) as shown in the doctor summary.
enum Listing {
    NotDeclared,
    Listed(usize),
    Failed(String),
}

impl<E: std::fmt::Display> From<std::result::Result<usize, E>> for Listing {
    fn from(result: std::result::Result<usize, E>) -> Self {
        match result {
            Ok(count) => Listing::Listed(count),
            Err(error) => Listing::Failed(error.to_string()),
        }
    }
}

impl Listing {
    fn cell(&self) -> String {
        match self {
            Listing::NotDeclared => "n/a".to_string(),
            Listing::Listed(count) => count.to_string(),
            Listing::Failed(_) => "error".to_string(),
        }
    }
}
