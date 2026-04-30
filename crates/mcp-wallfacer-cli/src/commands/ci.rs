use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use jsonschema::validator_for;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    differential::{boundary_payload, response_value},
    finding::{Finding, FindingKind, ReproInfo, Severity},
    sarif,
    target::Config,
};

#[derive(Debug, Args)]
pub struct CiArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    #[arg(long, value_enum, default_value_t = SeverityThreshold::Medium)]
    pub severity_threshold: SeverityThreshold,
    #[arg(long, default_value = "10m")]
    pub max_duration: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityThreshold {
    Low,
    Medium,
    High,
    Critical,
}

pub async fn run(args: CiArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let findings = run_schema_pass(&config).await?;
    let corpus = Corpus::new(config.output.corpus_dir.clone());
    for finding in &findings {
        corpus.write_finding(finding)?;
    }

    print_findings(&findings, args.format)?;

    let threshold = args.severity_threshold.into();
    if findings.iter().any(|finding| finding.severity >= threshold) {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_schema_pass(config: &Config) -> Result<Vec<Finding>> {
    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let tools = client.list_tools().await.context("failed to list tools")?;
    let mut findings = Vec::new();

    for tool in tools {
        let Some(schema) = &tool.output_schema else {
            continue;
        };
        let schema = serde_json::Value::Object((**schema).clone());
        let validator = validator_for(&schema)
            .with_context(|| format!("invalid output schema for tool `{}`", tool.name))?;
        let input_schema = serde_json::Value::Object((*tool.input_schema).clone());
        let payload = boundary_payload(&input_schema);
        let seed = 0;

        let outcome = client
            .call_tool(
                tool.name.as_ref(),
                payload.clone(),
                Duration::from_millis(config.target.timeout_ms),
            )
            .await;

        let CallOutcome::Ok(result) = outcome else {
            continue;
        };
        if result.is_error == Some(true) {
            continue;
        }

        let response = response_value(&result);
        let errors = validator
            .iter_errors(&response)
            .map(|error| format!("{} at instance path {}", error, error.instance_path()))
            .collect::<Vec<_>>();

        if !errors.is_empty() {
            findings.push(Finding::new(
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
            ));
        }
    }

    client.shutdown().await.ok();
    Ok(findings)
}

fn print_findings(findings: &[Finding], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(findings)?),
        OutputFormat::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif::to_sarif(findings, env!("CARGO_PKG_VERSION")))?
        ),
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

impl From<SeverityThreshold> for Severity {
    fn from(value: SeverityThreshold) -> Self {
        match value {
            SeverityThreshold::Low => Severity::Low,
            SeverityThreshold::Medium => Severity::Medium,
            SeverityThreshold::High => Severity::High,
            SeverityThreshold::Critical => Severity::Critical,
        }
    }
}
