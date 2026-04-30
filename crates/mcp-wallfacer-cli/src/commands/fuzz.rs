use std::{collections::HashSet, io::IsTerminal, path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use indicatif::{ProgressBar, ProgressStyle};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::Value;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind, ReproInfo},
    mutate::{generate_payload, GenMode},
    seed::derive_seed,
    target::Config,
};

#[derive(Debug, Args)]
pub struct FuzzArgs {
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long)]
    pub iterations: Option<u64>,
    #[arg(long, value_enum, default_value_t = FuzzMode::Mixed)]
    pub mode: FuzzMode,
    #[arg(long)]
    pub include: Vec<String>,
    #[arg(long)]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub max_tools: Option<usize>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FuzzMode {
    Conform,
    Adversarial,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: FuzzArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::new(config.output.corpus_dir.clone());
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let all_tools = client.list_tools().await.context("failed to list tools")?;
    let allow_list = config
        .allow_destructive
        .tools
        .iter()
        .cloned()
        .collect::<HashSet<_>>();

    let mut blocked = Vec::new();
    let mut tools = all_tools
        .into_iter()
        .filter(|tool| matches_filters(tool.name.as_ref(), &args.include, &args.exclude))
        .filter(|tool| {
            let destructive = is_destructive_tool(tool.name.as_ref(), tool.description.as_deref());
            if destructive && !allow_list.contains(tool.name.as_ref()) {
                blocked.push(tool.name.to_string());
                false
            } else {
                true
            }
        })
        .collect::<Vec<_>>();

    if let Some(max_tools) = args.max_tools {
        tools.truncate(max_tools);
    }

    eprintln!(
        "Will fuzz {} tools across {} iterations, allowed-destructive: {}, blocked: {:?}",
        tools.len(),
        args.iterations.unwrap_or(200),
        !allow_list.is_empty(),
        blocked
    );

    if args.dry_run {
        for tool in &tools {
            println!("{}", tool.name);
        }
        client.shutdown().await.ok();
        return Ok(());
    }

    let master_seed = args.seed.unwrap_or_else(rand::random);
    let iterations = args.iterations.unwrap_or(200);
    let total = tools.len() as u64 * iterations;
    let progress = progress_bar(total, args.format);
    let mut findings = Vec::new();

    for tool in tools {
        let tool_name = tool.name.to_string();
        let input_schema = Value::Object((*tool.input_schema).clone());

        for iteration in 0..iterations {
            if let Some(progress) = &progress {
                progress.inc(1);
            }

            let seed = derive_seed(master_seed, &tool_name, iteration);
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let payload = generate_payload(&input_schema, &mut rng, args.mode.into());

            match client
                .call_tool(
                    &tool_name,
                    payload.clone(),
                    Duration::from_millis(config.target.timeout_ms),
                )
                .await
            {
                CallOutcome::Ok(_) => {}
                CallOutcome::Hang(duration) => {
                    let finding = finding(
                        FindingKind::Hang {
                            ms: duration.as_millis() as u64,
                        },
                        &tool_name,
                        "tool call timed out",
                        format!("timeout exceeded after {duration:?}"),
                        seed,
                        payload,
                        config.target.transport_name(),
                    );
                    corpus.write_finding(&finding)?;
                    findings.push(finding);
                    client
                        .reconnect()
                        .await
                        .context("failed to reconnect after hang")?;
                    break;
                }
                CallOutcome::Crash(reason) => {
                    let finding = finding(
                        FindingKind::Crash,
                        &tool_name,
                        "server crashed during tool call",
                        reason,
                        seed,
                        payload,
                        config.target.transport_name(),
                    );
                    corpus.write_finding(&finding)?;
                    findings.push(finding);
                    client
                        .reconnect()
                        .await
                        .context("failed to reconnect after crash")?;
                    break;
                }
                CallOutcome::ProtocolError(message) => {
                    let finding = finding(
                        FindingKind::ProtocolError,
                        &tool_name,
                        "protocol error during tool call",
                        message,
                        seed,
                        payload,
                        config.target.transport_name(),
                    );
                    corpus.write_finding(&finding)?;
                    findings.push(finding);
                    client
                        .reconnect()
                        .await
                        .context("failed to reconnect after protocol error")?;
                    break;
                }
            }
        }
    }

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }
    client.shutdown().await.ok();

    print_findings(&findings, args.format)?;
    if findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

impl From<FuzzMode> for GenMode {
    fn from(value: FuzzMode) -> Self {
        match value {
            FuzzMode::Conform => GenMode::Conform,
            FuzzMode::Adversarial => GenMode::Adversarial,
            FuzzMode::Mixed => GenMode::Mixed,
        }
    }
}

fn finding(
    kind: FindingKind,
    tool: &str,
    message: impl Into<String>,
    details: impl Into<String>,
    seed: u64,
    payload: Value,
    transport: &str,
) -> Finding {
    Finding::new(
        kind,
        tool,
        message,
        details,
        ReproInfo {
            seed,
            tool_call: payload,
            transport: transport.to_string(),
        },
    )
}

fn progress_bar(total: u64, format: OutputFormat) -> Option<ProgressBar> {
    if format != OutputFormat::Human || !std::io::stderr().is_terminal() {
        return None;
    }

    let progress = ProgressBar::new(total);
    let style = ProgressStyle::with_template("{wide_bar} {pos}/{len} calls")
        .unwrap_or_else(|_| ProgressStyle::default_bar());
    progress.set_style(style);
    Some(progress)
}

fn print_findings(findings: &[Finding], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(findings)?);
        }
        OutputFormat::Human => {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(vec!["Tool", "Kind", "Severity", "Message"]);
            for finding in findings {
                table.add_row(vec![
                    Cell::new(&finding.tool),
                    Cell::new(format!("{:?}", finding.kind)),
                    Cell::new(format!("{:?}", finding.severity)),
                    Cell::new(&finding.message),
                ]);
            }
            println!("{table}");
        }
    }
    Ok(())
}

fn matches_filters(name: &str, includes: &[String], excludes: &[String]) -> bool {
    let included = includes.is_empty() || includes.iter().any(|pattern| glob_match(pattern, name));
    let excluded = excludes.iter().any(|pattern| glob_match(pattern, name));
    included && !excluded
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let mut remainder = text;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts = pattern.split('*').filter(|part| !part.is_empty());

    for (index, part) in parts.enumerate() {
        if index == 0 && anchored_start {
            if !remainder.starts_with(part) {
                return false;
            }
            remainder = &remainder[part.len()..];
            continue;
        }

        match remainder.find(part) {
            Some(position) => remainder = &remainder[position + part.len()..],
            None => return false,
        }
    }

    !anchored_end || remainder.is_empty()
}

fn is_destructive_tool(name: &str, description: Option<&str>) -> bool {
    const TERMS: &[&str] = &[
        "delete", "drop", "destroy", "truncate", "kill", "wipe", "purge", "reset",
    ];

    let mut text = name.to_lowercase();
    if let Some(description) = description {
        text.push(' ');
        text.push_str(&description.to_lowercase());
    }

    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| TERMS.iter().any(|term| word.starts_with(term)))
}
