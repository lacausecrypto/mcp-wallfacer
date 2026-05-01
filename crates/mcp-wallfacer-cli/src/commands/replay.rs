use std::{path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Args;
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind},
    redact::REDACTED_PLACEHOLDER,
    target::Config,
};

use crate::commands::unredact::unredact;

#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// Finding id (or unique prefix) to replay. Use `wallfacer corpus list`
    /// to discover available ids.
    pub id: String,
    /// Print the substituted call payload to stderr. Off by default so
    /// secrets never accidentally land in CI logs even if a developer is
    /// watching `wallfacer` over the shoulder.
    #[arg(long)]
    pub show_payload: bool,
}

pub async fn run(args: ReplayArgs, config_path: Option<&Path>) -> Result<()> {
    let (_path, config) = Config::load_from_lookup(config_path).context("failed to load config")?;
    let corpus = Corpus::from_config(&config.output);
    let finding = corpus.find_by_id(&args.id)?;

    // Phase F2: when a finding's payload contains `<redacted>` placeholders
    // (Phase A redacted them on persistence), look up
    // `WALLFACER_REPLAY_<KEY_UPPER>` for each placeholder and substitute.
    // The substituted payload is sent to the server but never printed
    // unless `--show-payload` is set explicitly.
    let (payload, missing_secrets) = unredact(&finding.repro.tool_call);
    if !missing_secrets.is_empty() {
        eprintln!(
            "note: replay payload still contains `{REDACTED_PLACEHOLDER}` for keys without a \
             matching env var: {missing_secrets:?}"
        );
        eprintln!(
            "      set WALLFACER_REPLAY_<KEY_UPPER> for each one to restore the original value."
        );
    }

    if args.show_payload {
        eprintln!(
            "replay payload (post-unredact):\n{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    }

    let client = Client::connect(&config.target)
        .await
        .context("failed to connect to MCP target")?;
    let outcome = client
        .call_tool(
            &finding.tool,
            payload,
            Duration::from_millis(config.target.timeout_ms),
        )
        .await;
    client.shutdown().await.ok();

    println!("{}", verdict(&finding, &outcome));
    if matches_kind(&finding.kind, &outcome) {
        Ok(())
    } else {
        // Reproduction failed: the finding no longer triggers under the
        // current target. CI uses this exit status to detect "fixed in
        // place" findings.
        bail!("replay did not reproduce the original outcome");
    }
}

fn verdict(finding: &Finding, outcome: &CallOutcome) -> String {
    match (&finding.kind, outcome) {
        (FindingKind::Crash, CallOutcome::Crash(_)) => "reproduced: same crash".to_string(),
        (FindingKind::Hang { .. }, CallOutcome::Hang(_)) => "reproduced: same hang".to_string(),
        (FindingKind::ProtocolError, CallOutcome::ProtocolError(_)) => {
            "reproduced: same protocol error".to_string()
        }
        (_, CallOutcome::Ok(_)) => "did not reproduce: tool call succeeded".to_string(),
        (_, CallOutcome::Hang(_)) => "did not reproduce: hang on this run".to_string(),
        (_, CallOutcome::Crash(_)) => "did not reproduce: different crash".to_string(),
        (_, CallOutcome::ProtocolError(message)) => {
            format!("did not reproduce: protocol error `{message}`")
        }
    }
}

fn matches_kind(kind: &FindingKind, outcome: &CallOutcome) -> bool {
    matches!(
        (kind, outcome),
        (FindingKind::Crash, CallOutcome::Crash(_))
            | (FindingKind::Hang { .. }, CallOutcome::Hang(_))
            | (FindingKind::ProtocolError, CallOutcome::ProtocolError(_))
    )
}
