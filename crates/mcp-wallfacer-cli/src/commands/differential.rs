use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use jsonschema::validator_for;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::Value;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    differential::{
        boundary_payload, inferred_schema_dir, load_schema, response_value, save_schema,
    },
    finding::{Finding, FindingKind, ReproInfo},
    mutate::{generate_payload, GenMode},
    seed::derive_seed,
    target::Config,
};

#[derive(Debug, Args)]
pub struct DifferentialArgs {
    #[arg(long)]
    pub learn: bool,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long, default_value_t = 20)]
    pub iterations: u64,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: DifferentialArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let tools = client.list_tools().await.context("failed to list tools")?;
    let schema_dir = inferred_schema_dir();

    if args.learn {
        let mut learned = 0usize;
        for tool in &tools {
            if let Some(schema) = &tool.output_schema {
                let schema = Value::Object((**schema).clone());
                save_schema(&schema_dir, tool.name.as_ref(), &schema)?;
                learned += 1;
            } else {
                eprintln!(
                    "Tool `{}` has no output schema; skipping baseline learning.",
                    tool.name
                );
            }
        }
        client.shutdown().await.ok();
        println!("learned {learned} output schema baselines");
        return Ok(());
    }

    let corpus = Corpus::new(config.output.corpus_dir.clone());
    let master_seed = args.seed.unwrap_or_else(rand::random);
    let mut findings = Vec::new();

    for tool in &tools {
        let schema = if let Some(schema) = &tool.output_schema {
            Some(Value::Object((**schema).clone()))
        } else {
            load_schema(&schema_dir, tool.name.as_ref())?
        };

        let Some(schema) = schema else {
            eprintln!(
                "Tool `{}` has no output schema and no inferred baseline. Run with `--learn` first.",
                tool.name
            );
            continue;
        };

        let validator = validator_for(&schema)
            .with_context(|| format!("invalid output schema for tool `{}`", tool.name))?;
        let input_schema = Value::Object((*tool.input_schema).clone());

        for iteration in 0..args.iterations {
            let seed = derive_seed(master_seed, tool.name.as_ref(), iteration);
            let payload = if iteration == 0 {
                boundary_payload(&input_schema)
            } else {
                let mut rng = ChaCha8Rng::seed_from_u64(seed);
                generate_payload(&input_schema, &mut rng, GenMode::Conform)
            };

            let outcome = client
                .call_tool(
                    tool.name.as_ref(),
                    payload.clone(),
                    Duration::from_millis(config.target.timeout_ms),
                )
                .await;

            match outcome {
                CallOutcome::Ok(result) if result.is_error == Some(true) => continue,
                CallOutcome::Ok(result) => {
                    let response = response_value(&result);
                    let errors = validator
                        .iter_errors(&response)
                        .map(|error| {
                            format!("{} at instance path {}", error, error.instance_path())
                        })
                        .collect::<Vec<_>>();

                    if errors.is_empty() {
                        continue;
                    }

                    let finding = Finding::new(
                        FindingKind::SchemaViolation,
                        tool.name.to_string(),
                        "tool response does not match output schema",
                        format!(
                            "{}\nobserved: {}",
                            errors.join("\n"),
                            serde_json::to_string_pretty(&response)?
                        ),
                        ReproInfo {
                            seed,
                            tool_call: payload,
                            transport: config.target.transport_name().to_string(),
                        },
                    );
                    corpus.write_finding(&finding)?;
                    findings.push(finding);
                    break;
                }
                CallOutcome::Hang(duration) => {
                    eprintln!(
                        "Tool `{}` timed out after {:?}; skipping.",
                        tool.name, duration
                    );
                    client.reconnect().await.ok();
                    break;
                }
                CallOutcome::Crash(reason) => {
                    eprintln!(
                        "Tool `{}` stopped responding: {}; skipping.",
                        tool.name, reason
                    );
                    client.reconnect().await.ok();
                    break;
                }
                CallOutcome::ProtocolError(message) => {
                    eprintln!(
                        "Tool `{}` returned protocol error: {}; skipping.",
                        tool.name, message
                    );
                    client.reconnect().await.ok();
                    break;
                }
            }
        }
    }

    client.shutdown().await.ok();
    print_findings(&findings, args.format)?;

    if findings.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
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
