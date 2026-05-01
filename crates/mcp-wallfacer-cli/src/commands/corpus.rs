use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use comfy_table::{presets::UTF8_FULL, Cell, Table};
use serde_json::{json, Value};
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind},
    property::{dsl, runner},
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
        /// Phase AC.1 (v0.8) — re-evaluate the exact invariant
        /// that produced the finding on every shrink trial,
        /// instead of the coarse `ShrinkTargetKind` bucket.
        ///
        /// Pass the YAML file (or pack) the invariant lives in;
        /// the invariant whose `name` matches the finding's
        /// `kind.invariant` is loaded and its assertions become
        /// the predicate. Only meaningful for `property_failure`
        /// findings — other kinds keep using the transport-level
        /// classifier.
        #[arg(long)]
        invariants: Option<PathBuf>,
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
        CorpusCommand::Minimize {
            id,
            replay,
            invariants,
        } => minimize(&corpus, config.as_ref(), &id, replay, invariants.as_deref()).await,
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

async fn minimize(
    corpus: &Corpus,
    config: Option<&Config>,
    id: &str,
    replay: bool,
    invariants_path: Option<&Path>,
) -> Result<()> {
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

    // Phase AC.1 — when `--invariants <path>` is set and the
    // finding is a PropertyFailure, load the matching invariant
    // and use it as the predicate so each shrink trial re-runs
    // the *exact* assertions that fired originally. Other finding
    // kinds (or no path) keep the transport-level classifier.
    let invariant = match (invariants_path, &finding.kind) {
        (Some(path), FindingKind::PropertyFailure { invariant: name }) => {
            let source = fs::read_to_string(path)
                .with_context(|| format!("failed to read invariants file {}", path.display()))?;
            let file = dsl::parse(&source).context("failed to parse invariants")?;
            let found = file
                .invariants
                .iter()
                .find(|i| &i.name == name)
                .cloned()
                .with_context(|| {
                    format!(
                        "invariants file `{}` has no invariant named `{name}`",
                        path.display()
                    )
                })?;
            Some(found)
        }
        (Some(path), other) => {
            eprintln!(
                "note: --invariants {} ignored: finding kind is `{}`, not `property_failure`",
                path.display(),
                other.keyword()
            );
            None
        }
        (None, _) => None,
    };

    let original = finding.repro.tool_call.clone();
    let tool = finding.tool.clone();
    let timeout = Duration::from_millis(config.target.timeout_ms);
    let client = Client::connect(&config.target)
        .await
        .with_context(|| "failed to connect to MCP target for replay-based shrink")?;

    eprintln!(
        "shrinking finding `{id}` (tool=`{tool}`, kind={:?}) — each trial is one tool call against the target{}",
        target_kind,
        if invariant.is_some() {
            " (per-invariant predicate)"
        } else {
            ""
        }
    );

    // For per-invariant shrinking we need the live tool's
    // metadata so `evaluate_with_tool` can inject `$.tool`. Look
    // it up once, before the shrink loop, so we don't pay the
    // listing cost on every trial.
    let live_tool = if invariant.is_some() {
        client
            .list_tools()
            .await
            .ok()
            .and_then(|tools| tools.into_iter().find(|t| t.name.as_ref() == tool))
    } else {
        None
    };

    let result = wallfacer_core::shrink::shrink_async(&original, |candidate| {
        let client = client.clone();
        let tool = tool.clone();
        let invariant = invariant.clone();
        let live_tool = live_tool.clone();
        async move {
            let outcome = client.call_tool(&tool, candidate.clone(), timeout).await;
            if let Some(invariant) = invariant {
                // Per-invariant predicate: shape the response the
                // same way `PropertyPlan::execute` does, then
                // re-run the assertions. "Still fires" means the
                // assertions failed — i.e. the trial input still
                // breaks the same invariant.
                let response = call_outcome_to_response(&outcome);
                runner::evaluate_with_tool(&invariant, candidate, response, live_tool.as_ref())
                    .is_err()
            } else {
                target_kind.matches_outcome(&outcome)
            }
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

/// Phase AC.1 — mirrors the response shape `PropertyPlan::execute`
/// builds in `wallfacer_core::run::property`. Re-runs of an
/// invariant must see the same `{content, isError}` envelope shape
/// as the original run, otherwise the JSONPath assertions wouldn't
/// match the same fields.
fn call_outcome_to_response(outcome: &CallOutcome) -> Value {
    match outcome {
        CallOutcome::Ok(result) => serde_json::to_value(result).unwrap_or(Value::Null),
        CallOutcome::Hang(duration) => json!({
            "content": [{"type": "text", "text": format!("timeout after {duration:?}")}],
            "isError": true,
        }),
        CallOutcome::Crash(reason) => json!({
            "content": [{"type": "text", "text": reason}],
            "isError": true,
        }),
        CallOutcome::ProtocolError(message) => json!({
            "content": [{"type": "text", "text": message}],
            "isError": true,
        }),
    }
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
