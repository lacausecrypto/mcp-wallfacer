use std::{path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde_json::{Map, Value};
use wallfacer_core::{
    client::{CallOutcome, Client},
    corpus::Corpus,
    finding::{Finding, FindingKind},
    redact::REDACTED_PLACEHOLDER,
    target::Config,
};

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

/// Walks the JSON payload and replaces every `<redacted>` string with the
/// value of `WALLFACER_REPLAY_<KEY_UPPER>` from the environment, where
/// `KEY` is the parent JSON object key (e.g. `password` →
/// `WALLFACER_REPLAY_PASSWORD`). Returns the substituted payload and the
/// list of keys that had no matching env var.
fn unredact(value: &Value) -> (Value, Vec<String>) {
    let mut missing = Vec::new();
    let substituted = unredact_inner(value, &mut missing);
    (substituted, missing)
}

fn unredact_inner(value: &Value, missing: &mut Vec<String>) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, child) in map {
                let new_value = if is_placeholder(child) {
                    let env_var = format!("WALLFACER_REPLAY_{}", key.to_ascii_uppercase());
                    match std::env::var(&env_var) {
                        Ok(v) => Value::String(v),
                        Err(_) => {
                            missing.push(key.clone());
                            child.clone()
                        }
                    }
                } else {
                    unredact_inner(child, missing)
                };
                out.insert(key.clone(), new_value);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| unredact_inner(item, missing))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn is_placeholder(value: &Value) -> bool {
    matches!(value, Value::String(s) if s == REDACTED_PLACEHOLDER)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unredact_substitutes_from_env() {
        std::env::set_var("WALLFACER_REPLAY_PASSWORD", "real-secret");
        std::env::set_var("WALLFACER_REPLAY_API_KEY", "real-key");
        let input = json!({
            "user": "alice",
            "password": "<redacted>",
            "api_key": "<redacted>"
        });
        let (output, missing) = unredact(&input);
        assert_eq!(output["user"], json!("alice"));
        assert_eq!(output["password"], json!("real-secret"));
        assert_eq!(output["api_key"], json!("real-key"));
        assert!(missing.is_empty());
    }

    #[test]
    fn unredact_reports_missing_env_vars() {
        std::env::remove_var("WALLFACER_REPLAY_TOKEN");
        let input = json!({"token": "<redacted>", "name": "alice"});
        let (output, missing) = unredact(&input);
        assert_eq!(output["token"], json!("<redacted>"));
        assert_eq!(missing, vec!["token".to_string()]);
    }

    #[test]
    fn unredact_walks_nested_objects_and_arrays() {
        std::env::set_var("WALLFACER_REPLAY_PASSWORD", "real-secret");
        let input = json!({
            "users": [
                {"name": "alice", "password": "<redacted>"},
                {"name": "bob", "password": "<redacted>"}
            ]
        });
        let (output, _) = unredact(&input);
        assert_eq!(output["users"][0]["password"], json!("real-secret"));
        assert_eq!(output["users"][1]["password"], json!("real-secret"));
    }
}
