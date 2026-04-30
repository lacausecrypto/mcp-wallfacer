//! Redaction of secrets before persistence.
//!
//! Findings and target configuration may contain bearer tokens, cookies, or
//! payload fields named like secrets (`api_key`, `password`, ...). Anything
//! that lands on disk in `.wallfacer/` or in CI artefacts must first be
//! filtered through [`Redact::redacted`] so cleartext secrets do not leak into
//! corpus files, SARIF output, or shared logs.

use serde_json::{Map, Value};

use crate::{
    finding::{Finding, ReproInfo},
    target::{Target, Transport},
};

/// Placeholder substituted for any value that matched a redaction pattern.
pub const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// Trait implemented by types that can produce a copy with sensitive fields
/// scrubbed. Implementations must be **idempotent** and **non-destructive**:
/// they return a new value rather than mutating in place, so callers can keep
/// the original around for in-process use (e.g. reproducing a call) while
/// persisting only the scrubbed copy.
pub trait Redact {
    /// Returns a deep copy with sensitive fields replaced by
    /// [`REDACTED_PLACEHOLDER`].
    fn redacted(&self) -> Self;
}

/// Returns `true` if a HTTP header name should have its value masked before
/// persistence.
///
/// Matches (case-insensitive):
/// * `Authorization`, `Proxy-Authorization`
/// * `Cookie`, `Set-Cookie`
/// * any name containing `token`, `secret`, `password`, `bearer`, `api-key`,
///   `api_key`, `apikey`
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) || contains_secret_marker(&lower)
}

/// Returns `true` if a JSON object key likely identifies a secret value.
///
/// The match is case-insensitive and looks for the same markers as
/// [`is_sensitive_header`], plus standalone `auth` (only as a whole word, to
/// avoid matching unrelated names like `author`).
pub fn is_sensitive_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if contains_secret_marker(&lower) {
        return true;
    }
    // Standalone `auth` word. We split on common separators so `auth_kind` or
    // `kind-auth` match, while `author` and `authentik` do not.
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|segment| segment == "auth")
}

fn contains_secret_marker(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "bearer",
        "api-key",
        "api_key",
        "apikey",
        "private-key",
        "private_key",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Recursively redacts a JSON value: any object entry whose key matches
/// [`is_sensitive_key`] has its value replaced by [`REDACTED_PLACEHOLDER`].
/// Arrays and nested objects are walked.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, child) in map {
                if is_sensitive_key(key) {
                    out.insert(key.clone(), Value::String(REDACTED_PLACEHOLDER.to_string()));
                } else {
                    out.insert(key.clone(), redact_json(child));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

impl Redact for Target {
    fn redacted(&self) -> Self {
        let transport = match &self.transport {
            Transport::Stdio { command, args, env } => {
                let env = env
                    .iter()
                    .map(|(name, value)| {
                        let masked = if is_sensitive_key(name) {
                            REDACTED_PLACEHOLDER.to_string()
                        } else {
                            value.clone()
                        };
                        (name.clone(), masked)
                    })
                    .collect();
                Transport::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    env,
                }
            }
            Transport::Http { url, headers } => {
                let headers = headers
                    .iter()
                    .map(|(name, value)| {
                        let masked = if is_sensitive_header(name) {
                            REDACTED_PLACEHOLDER.to_string()
                        } else {
                            value.clone()
                        };
                        (name.clone(), masked)
                    })
                    .collect();
                Transport::Http {
                    url: url.clone(),
                    headers,
                }
            }
        };
        Self {
            transport,
            timeout_ms: self.timeout_ms,
        }
    }
}

impl Redact for ReproInfo {
    fn redacted(&self) -> Self {
        Self {
            seed: self.seed,
            tool_call: redact_json(&self.tool_call),
            transport: self.transport.clone(),
            composition_trail: self.composition_trail.clone(),
        }
    }
}

impl Redact for Finding {
    fn redacted(&self) -> Self {
        Self {
            id: self.id.clone(),
            kind: self.kind.clone(),
            severity: self.severity,
            tool: self.tool.clone(),
            message: self.message.clone(),
            details: self.details.clone(),
            repro: self.repro.redacted(),
            timestamp: self.timestamp,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn header_authorization_is_sensitive() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("AUTHORIZATION"));
    }

    #[test]
    fn header_cookie_variants_are_sensitive() {
        assert!(is_sensitive_header("Cookie"));
        assert!(is_sensitive_header("Set-Cookie"));
        assert!(is_sensitive_header("set-cookie"));
        assert!(is_sensitive_header("Proxy-Authorization"));
    }

    #[test]
    fn header_x_token_pattern_is_sensitive() {
        assert!(is_sensitive_header("X-API-Token"));
        assert!(is_sensitive_header("X-Auth-Token"));
        assert!(is_sensitive_header("x-custom-token"));
        assert!(is_sensitive_header("X-Bearer"));
    }

    #[test]
    fn header_api_key_variants_are_sensitive() {
        assert!(is_sensitive_header("X-API-Key"));
        assert!(is_sensitive_header("Api-Key"));
        assert!(is_sensitive_header("apikey"));
    }

    #[test]
    fn header_benign_is_not_sensitive() {
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("Accept"));
        assert!(!is_sensitive_header("User-Agent"));
        assert!(!is_sensitive_header("X-Request-Id"));
    }

    #[test]
    fn key_password_is_sensitive() {
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("passwd"));
        assert!(is_sensitive_key("user_password"));
    }

    #[test]
    fn key_secret_and_token_variants_are_sensitive() {
        assert!(is_sensitive_key("secret"));
        assert!(is_sensitive_key("clientSecret"));
        assert!(is_sensitive_key("access_token"));
        assert!(is_sensitive_key("private_key"));
    }

    #[test]
    fn key_auth_word_is_sensitive_only_as_whole_word() {
        assert!(is_sensitive_key("auth"));
        assert!(is_sensitive_key("auth_kind"));
        assert!(is_sensitive_key("kind-auth"));
        // "author" and "authentik" must NOT trigger.
        assert!(!is_sensitive_key("author"));
        assert!(!is_sensitive_key("authority"));
    }

    #[test]
    fn key_benign_is_not_sensitive() {
        assert!(!is_sensitive_key("name"));
        assert!(!is_sensitive_key("id"));
        assert!(!is_sensitive_key("value"));
        assert!(!is_sensitive_key("count"));
    }

    #[test]
    fn redact_json_walks_nested_objects() {
        let input = json!({
            "user": "alice",
            "credentials": {
                "password": "p@ss",
                "api_key": "secret-123"
            },
            "items": [
                { "value": 1, "token": "t-1" },
                { "value": 2, "token": "t-2" }
            ]
        });
        let output = redact_json(&input);
        assert_eq!(output["user"], json!("alice"));
        assert_eq!(
            output["credentials"]["password"],
            json!(REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            output["credentials"]["api_key"],
            json!(REDACTED_PLACEHOLDER)
        );
        assert_eq!(output["items"][0]["value"], json!(1));
        assert_eq!(output["items"][0]["token"], json!(REDACTED_PLACEHOLDER));
        assert_eq!(output["items"][1]["token"], json!(REDACTED_PLACEHOLDER));
    }

    #[test]
    fn redact_is_idempotent() {
        let input = json!({"password": "x", "api_key": "y"});
        let once = redact_json(&input);
        let twice = redact_json(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn redact_target_http_masks_authorization() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer abc123".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let target = Target {
            transport: Transport::Http {
                url: "http://localhost".to_string(),
                headers,
            },
            timeout_ms: 1000,
        };
        let redacted = target.redacted();
        let Transport::Http { headers, .. } = &redacted.transport else {
            panic!("expected http transport");
        };
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            headers.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn redact_target_stdio_masks_secret_env() {
        let mut env = HashMap::new();
        env.insert("API_TOKEN".to_string(), "tok-1".to_string());
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let target = Target {
            transport: Transport::Stdio {
                command: "python3".to_string(),
                args: vec!["server.py".to_string()],
                env,
            },
            timeout_ms: 1000,
        };
        let redacted = target.redacted();
        let Transport::Stdio { env, .. } = &redacted.transport else {
            panic!("expected stdio transport");
        };
        assert_eq!(
            env.get("API_TOKEN").map(String::as_str),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn redact_finding_masks_repro_payload() {
        use crate::finding::{Finding, FindingKind};
        let finding = Finding::new(
            FindingKind::Crash,
            "tool",
            "msg",
            "details",
            ReproInfo {
                seed: 1,
                tool_call: json!({"password": "p", "name": "alice"}),
                transport: "stdio".to_string(),
                composition_trail: Vec::new(),
            },
        );
        let original_id = finding.id.clone();
        let redacted = finding.redacted();
        // ID is preserved (computed from the original payload).
        assert_eq!(redacted.id, original_id);
        assert_eq!(
            redacted.repro.tool_call["password"],
            json!(REDACTED_PLACEHOLDER)
        );
        assert_eq!(redacted.repro.tool_call["name"], json!("alice"));
    }
}
