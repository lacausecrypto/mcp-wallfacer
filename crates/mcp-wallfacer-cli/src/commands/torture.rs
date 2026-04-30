use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use futures::future::join_all;
use serde_json::{json, Value};
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    differential::response_value,
    finding::{Finding, FindingKind, ReproInfo},
    target::Config,
};

#[derive(Debug, Args)]
pub struct TortureArgs {
    #[arg(long, value_enum, default_value_t = TortureMode::Parallel)]
    pub mode: TortureMode,
    #[arg(long)]
    pub target_tool: Option<String>,
    #[arg(long, default_value_t = 50)]
    pub concurrency: usize,
    #[arg(long, default_value = "30s")]
    pub duration: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TortureMode {
    Parallel,
    StateLeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: TortureArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::new(config.output.corpus_dir.clone());
    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let timeout = parse_duration(&args.duration).unwrap_or_else(|| Duration::from_secs(30));

    let findings = match args.mode {
        TortureMode::Parallel => {
            run_parallel(
                &client,
                &config,
                args.target_tool.as_deref(),
                args.concurrency,
                timeout,
            )
            .await?
        }
        TortureMode::StateLeak => run_state_leak(&client, &config, timeout).await?,
    };

    for finding in &findings {
        corpus.write_finding(finding)?;
    }

    client.shutdown().await.ok();
    print_findings(&findings, args.format)?;

    if findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

async fn run_parallel(
    client: &Client,
    config: &Config,
    target_tool: Option<&str>,
    concurrency: usize,
    timeout: Duration,
) -> Result<Vec<Finding>> {
    let tool = target_tool.unwrap_or("counter_inc");
    let payload = json!({});
    let calls = (0..concurrency)
        .map(|_| client.call_tool(tool, payload.clone(), timeout))
        .collect::<Vec<_>>();
    let outcomes = join_all(calls).await;

    let success_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, CallOutcome::Ok(_)))
        .count();

    let mut findings = Vec::new();
    if success_count < concurrency {
        findings.push(Finding::new(
            FindingKind::ProtocolError,
            tool.to_string(),
            "parallel calls did not all complete successfully",
            format!("{success_count}/{concurrency} calls completed"),
            ReproInfo {
                seed: 0,
                tool_call: payload.clone(),
                transport: config.target.transport_name().to_string(),
            },
        ));
    }

    if tool == "counter_inc" {
        let counter = match client.call_tool("counter_get", json!({}), timeout).await {
            CallOutcome::Ok(result) => response_value(&result)
                .get("counter")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            _ => 0,
        };

        if counter != concurrency {
            findings.push(Finding::new(
                FindingKind::PropertyFailure {
                    invariant: "counter_inc must be atomic".to_string(),
                },
                tool.to_string(),
                "counter lost updates under parallel calls",
                format!("expected counter {concurrency}, observed {counter}"),
                ReproInfo {
                    seed: 0,
                    tool_call: payload,
                    transport: config.target.transport_name().to_string(),
                },
            ));
        }
    }

    Ok(findings)
}

async fn run_state_leak(
    client: &Client,
    config: &Config,
    timeout: Duration,
) -> Result<Vec<Finding>> {
    let set_payload = json!({"key": "secret", "value": "alice-data"});
    let get_payload = json!({"key": "secret"});

    let _ = client
        .call_tool("session_set", set_payload.clone(), timeout)
        .await;
    let observed = match client
        .call_tool("session_get", get_payload.clone(), timeout)
        .await
    {
        CallOutcome::Ok(result) => response_value(&result),
        other => json!({"unexpected": format!("{other:?}")}),
    };

    let leaked = observed.get("value").is_some_and(|value| !value.is_null());
    if leaked {
        Ok(vec![Finding::new(
            FindingKind::StateLeak,
            "session_get",
            "session data is visible outside its expected boundary",
            format!(
                "observed response: {}",
                serde_json::to_string_pretty(&observed)?
            ),
            ReproInfo {
                seed: 0,
                tool_call: get_payload,
                transport: config.target.transport_name().to_string(),
            },
        )])
    } else {
        Ok(Vec::new())
    }
}

fn parse_duration(value: &str) -> Option<Duration> {
    if let Some(seconds) = value.strip_suffix('s') {
        return seconds.parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return milliseconds.parse::<u64>().ok().map(Duration::from_millis);
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

fn print_findings(findings: &[Finding], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(findings)?),
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
