use std::{path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use serde_json::Value;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind},
    redact::REDACTED_PLACEHOLDER,
    target::{default_corpus_dir, Config},
};

use crate::commands::unredact::unredact;

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
        /// Phase X (v0.7) — actually shrink the input by replaying
        /// against the live target. Each delta-debug trial is one
        /// `tools/call` round-trip; the smallest input that still
        /// reproduces the original finding kind is written to disk
        /// next to the original (`<id>.minimised.json`).
        ///
        /// Without this flag, `minimize` stays inspect-only
        /// (prints the finding verbatim — same behaviour as
        /// v0.6.x).
        #[arg(long)]
        replay: bool,
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
        CorpusCommand::Minimize { id, replay } => {
            minimize(&corpus, config.as_ref(), &id, replay).await
        }
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
    // The persisted payload carries `<redacted>` placeholders; substitute
    // them from `WALLFACER_REPLAY_<KEY_UPPER>` so the server sees the
    // real values rather than the literal placeholder. Identical
    // behaviour to `wallfacer replay <id>`.
    let (payload, missing) = unredact(&finding.repro.tool_call);
    if !missing.is_empty() {
        eprintln!(
            "note: corpus replay payload still contains `{REDACTED_PLACEHOLDER}` for keys \
             without a matching env var: {missing:?}"
        );
        eprintln!(
            "      set WALLFACER_REPLAY_<KEY_UPPER> for each one to restore the original value."
        );
    }
    let outcome = client
        .call_tool(&finding.tool, payload, Duration::from_millis(timeout_ms))
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

async fn minimize(corpus: &Corpus, config: Option<&Config>, id: &str, replay: bool) -> Result<()> {
    let finding = corpus.find_by_id(id)?;

    if !replay {
        // Inspect-only mode (v0.6.x and earlier behaviour). Print
        // the finding so authors can hand-shrink offline.
        eprintln!(
            "note: `corpus minimize` without --replay is inspect-only. Pass --replay to \
             shrink the input by re-driving it against the configured target."
        );
        println!("{}", serde_json::to_string_pretty(&finding)?);
        return Ok(());
    }

    // Phase X — live shrinking via `--replay`. Connect to the
    // target, then iteratively shrink the input. Each shrink
    // trial is one round-trip; the predicate compares the
    // observed CallOutcome's kind against the original finding's
    // kind class (Crash / Hang / ProtocolError vs PropertyFailure /
    // SchemaViolation are kept apart).
    let config = config.ok_or_else(|| {
        anyhow::anyhow!(
            "--replay needs a wallfacer.toml; run from a directory with one or pass --config"
        )
    })?;
    let target_kind = wallfacer_core::shrink::ShrinkTargetKind::from_finding_kind(&finding.kind);

    let original = finding.repro.tool_call.clone();
    let tool = finding.tool.clone();
    let timeout = Duration::from_millis(config.target.timeout_ms);
    let client = Client::connect(&config.target)
        .await
        .with_context(|| "failed to connect to MCP target for replay-based shrink")?;

    eprintln!(
        "shrinking finding `{id}` (tool=`{tool}`, kind={:?}) — each trial is one tool call against the target",
        target_kind
    );

    let result = wallfacer_core::shrink::shrink_async(&original, |candidate| {
        let client = client.clone();
        let tool = tool.clone();
        async move {
            let outcome = client.call_tool(&tool, candidate, timeout).await;
            target_kind.matches_outcome(&outcome)
        }
    })
    .await;

    client.shutdown().await.ok();

    eprintln!(
        "shrunk in {} step(s): {} bytes \u{2192} {} bytes ({:.0}% of original)",
        result.steps,
        result.byte_size.0,
        result.byte_size.1,
        if result.byte_size.0 == 0 {
            0.0
        } else {
            (result.byte_size.1 as f64 / result.byte_size.0 as f64) * 100.0
        }
    );
    println!("{}", serde_json::to_string_pretty(&result.minimised)?);
    Ok(())
}

fn compact_json(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    if text.len() <= 120 {
        return text;
    }
    // Slice on a UTF-8 char boundary so multi-byte codepoints (escape
    // sequences from server output, emoji in error messages, ...) don't
    // panic the formatter mid-character.
    let mut cut = 120;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &text[..cut])
}
