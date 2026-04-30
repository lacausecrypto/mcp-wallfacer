use std::{fs, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind, ReproInfo},
    property::{dsl, runner},
    seed::derive_seed,
    target::Config,
};

#[derive(Debug, Args)]
pub struct PropertyArgs {
    pub invariants: std::path::PathBuf,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long, default_value_t = 100)]
    pub cases: u32,
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

pub async fn run(args: PropertyArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let source = fs::read_to_string(&args.invariants).with_context(|| {
        format!(
            "failed to read invariants file {}",
            args.invariants.display()
        )
    })?;
    let file = dsl::parse(&source).context("failed to parse invariants")?;
    if file.version != 1 {
        bail!("unsupported invariants version {}", file.version);
    }

    let corpus = Corpus::new(config.output.corpus_dir.clone());
    let mut client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let master_seed = args.seed.unwrap_or_else(rand::random);
    let mut findings = Vec::new();

    for invariant in &file.invariants {
        let cases = invariant.cases.unwrap_or(args.cases).max(1);

        for case_index in 0..cases {
            let seed = derive_seed(master_seed, &invariant.name, case_index as u64);
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let input = runner::input_for_case(invariant, case_index, &mut rng);
            let response = call_for_property(
                &mut client,
                &invariant.tool,
                input.clone(),
                Duration::from_millis(config.target.timeout_ms),
            )
            .await?;

            if let Err(error) = runner::evaluate(invariant, input.clone(), response.clone()) {
                let finding = Finding::new(
                    FindingKind::PropertyFailure {
                        invariant: invariant.name.clone(),
                    },
                    invariant.tool.clone(),
                    "property invariant failed",
                    format!(
                        "{error}\ninput: {}\nresponse: {}",
                        serde_json::to_string_pretty(&input)?,
                        serde_json::to_string_pretty(&response)?
                    ),
                    ReproInfo {
                        seed,
                        tool_call: input,
                        transport: config.target.transport_name().to_string(),
                    },
                );
                corpus.write_finding(&finding)?;
                findings.push(finding);
                break;
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

async fn call_for_property(
    client: &mut Client,
    tool: &str,
    input: Value,
    timeout: Duration,
) -> Result<Value> {
    match client.call_tool(tool, input, timeout).await {
        CallOutcome::Ok(result) => Ok(serde_json::to_value(result)?),
        CallOutcome::Hang(duration) => {
            client.reconnect().await.ok();
            Ok(json!({
                "content": [{"type": "text", "text": format!("timeout after {duration:?}")}],
                "isError": true
            }))
        }
        CallOutcome::Crash(reason) => {
            client.reconnect().await.ok();
            Ok(json!({
                "content": [{"type": "text", "text": reason}],
                "isError": true
            }))
        }
        CallOutcome::ProtocolError(message) => {
            client.reconnect().await.ok();
            Ok(json!({
                "content": [{"type": "text", "text": message}],
                "isError": true
            }))
        }
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
