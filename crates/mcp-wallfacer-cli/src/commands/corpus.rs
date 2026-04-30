use std::{path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use serde_json::Value;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind},
    target::{default_corpus_dir, Config},
};

#[derive(Debug, Args)]
pub struct CorpusArgs {
    #[command(subcommand)]
    pub command: CorpusCommand,
}

#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    List,
    Show {
        id: String,
    },
    Replay {
        id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Minimize {
        id: String,
    },
}

pub async fn run(args: CorpusArgs, config_path: Option<&Path>) -> Result<()> {
    let config = Config::load_from_lookup(config_path)
        .ok()
        .map(|(_, config)| config);
    let corpus_dir = config
        .as_ref()
        .map(|config| config.output.corpus_dir.clone())
        .unwrap_or_else(default_corpus_dir);
    let corpus = Corpus::new(corpus_dir);

    match args.command {
        CorpusCommand::List => list(&corpus),
        CorpusCommand::Show { id } => show(&corpus, &id),
        CorpusCommand::Replay { id, all } => replay(&corpus, config.as_ref(), id, all).await,
        CorpusCommand::Minimize { id } => minimize(&corpus, &id),
    }
}

fn list(corpus: &Corpus) -> Result<()> {
    let findings = corpus.list_findings()?;
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["ID", "Tool", "Kind", "Severity", "Message"]);
    for finding in findings {
        table.add_row(vec![
            Cell::new(finding.id),
            Cell::new(finding.tool),
            Cell::new(format!("{:?}", finding.kind)),
            Cell::new(format!("{:?}", finding.severity)),
            Cell::new(finding.message),
        ]);
    }
    println!("{table}");
    Ok(())
}

fn show(corpus: &Corpus, id: &str) -> Result<()> {
    let finding = corpus.find_by_id(id)?;
    println!("{}", serde_json::to_string_pretty(&finding)?);
    Ok(())
}

async fn replay(
    corpus: &Corpus,
    config: Option<&Config>,
    id: Option<String>,
    all: bool,
) -> Result<()> {
    let Some(config) = config else {
        bail!("replay requires wallfacer.toml or --config <path>");
    };

    let findings = if all {
        corpus.list_findings()?
    } else {
        vec![corpus.find_by_id(id.as_deref().context("pass a finding id or use `--all`")?)?]
    };

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["ID", "Tool", "Replay"]);

    for finding in findings {
        let client = Client::connect(&config.target)
            .await
            .context("failed to connect to MCP target")?;
        let status = replay_one(&client, &finding, config.target.timeout_ms).await;
        client.shutdown().await.ok();
        table.add_row(vec![
            Cell::new(finding.id),
            Cell::new(finding.tool),
            Cell::new(status),
        ]);
    }

    println!("{table}");
    Ok(())
}

async fn replay_one(client: &Client, finding: &Finding, timeout_ms: u64) -> String {
    let outcome = client
        .call_tool(
            &finding.tool,
            finding.repro.tool_call.clone(),
            Duration::from_millis(timeout_ms),
        )
        .await;

    match (&finding.kind, outcome) {
        (FindingKind::Crash, CallOutcome::Crash(_)) => "same crash".to_string(),
        (FindingKind::Hang { .. }, CallOutcome::Hang(_)) => "same hang".to_string(),
        (FindingKind::ProtocolError, CallOutcome::ProtocolError(_)) => {
            "same protocol error".to_string()
        }
        (_, CallOutcome::Ok(result)) => {
            let value = serde_json::to_value(result).unwrap_or(Value::Null);
            format!("replayed ok: {}", compact_json(&value))
        }
        (_, CallOutcome::Hang(_)) => "replayed hang".to_string(),
        (_, CallOutcome::Crash(message)) => format!("replayed crash: {message}"),
        (_, CallOutcome::ProtocolError(message)) => format!("replayed protocol error: {message}"),
    }
}

fn minimize(corpus: &Corpus, id: &str) -> Result<()> {
    let finding = corpus.find_by_id(id)?;
    println!("{}", serde_json::to_string_pretty(&finding)?);
    Ok(())
}

fn compact_json(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    if text.len() > 120 {
        format!("{}...", &text[..120])
    } else {
        text
    }
}
