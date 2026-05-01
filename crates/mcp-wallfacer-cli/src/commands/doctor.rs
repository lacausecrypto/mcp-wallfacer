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
    // Capability-aware listing: `list_resources` / `list_prompts`
    // already short-circuit to an empty vec when the server didn't
    // advertise the capability, but we want the doctor table to show
    // "n/a" rather than "0" so the operator can tell "server
    // declares the cap, vector is empty" from "server didn't declare
    // the cap at all".
    let capabilities = client.server_capabilities().await;
    let supports_resources = capabilities
        .as_ref()
        .is_some_and(|caps| caps.resources.is_some());
    let supports_prompts = capabilities
        .as_ref()
        .is_some_and(|caps| caps.prompts.is_some());
    let resources = if supports_resources {
        client
            .list_resources()
            .await
            .context("failed to list resources")?
    } else {
        Vec::new()
    };
    let prompts = if supports_prompts {
        client
            .list_prompts()
            .await
            .context("failed to list prompts")?
    } else {
        Vec::new()
    };

    let mut summary = Table::new();
    summary.load_preset(UTF8_FULL);
    summary.set_header(vec!["Config", "Transport", "Tools", "Resources", "Prompts"]);
    summary.add_row(vec![
        Cell::new(path.display()),
        Cell::new(config.target.transport_name()),
        Cell::new(tools.len()),
        Cell::new(if supports_resources {
            resources.len().to_string()
        } else {
            "n/a".to_string()
        }),
        Cell::new(if supports_prompts {
            prompts.len().to_string()
        } else {
            "n/a".to_string()
        }),
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
