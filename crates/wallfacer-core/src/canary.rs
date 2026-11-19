//! Canary secret planted in the environment of stdio servers.
//!
//! Wallfacer spawns every stdio target with [`ENV_VAR`] set to a random
//! value that never appears in any request. A response that contains it
//! can only come from the server disclosing its own environment — a
//! debug/status tool dumping `process.env`, a template or shell
//! expansion of `$VAR` in user input, an error that serialises the
//! config — so detection has no false positive from input reflection,
//! unlike probing with secret-looking input strings.
//!
//! The value is random per wallfacer process and is not a credential:
//! it is safe to persist in findings. HTTP targets are not spawned by
//! wallfacer, so nothing is planted and nothing can match.

use std::sync::OnceLock;

use rand::RngCore;

/// Environment variable holding the canary. Named like a real secret so
/// servers that redact `*SECRET*` variables before display get credit
/// for it.
pub const ENV_VAR: &str = "WALLFACER_CANARY_SECRET";

/// Fixed prefix of every canary value. Packs match `wfcanary_[0-9a-f]{32}`
/// without knowing the value of the current run.
pub const PREFIX: &str = "wfcanary_";

/// The canary value for this process: [`PREFIX`] + 32 hex digits.
pub fn value() -> &'static str {
    static VALUE: OnceLock<String> = OnceLock::new();
    VALUE.get_or_init(|| {
        let mut bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        format!("{PREFIX}{}", hex::encode(bytes))
    })
}

/// True when `text` contains this process's canary value.
pub fn leaked_in(text: &str) -> bool {
    text.contains(value())
}

/// True when any part of a tool result (text, structured content,
/// resource bodies, `_meta`) contains the canary value.
pub fn leaked_in_result(result: &rmcp::model::CallToolResult) -> bool {
    serde_json::to_string(result).is_ok_and(|json| leaked_in(&json))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn value_is_stable_and_shaped() {
        assert_eq!(value(), value());
        let suffix = value().strip_prefix(PREFIX).expect("prefix");
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn detection_needs_the_value_not_the_name() {
        assert!(!leaked_in(&format!("${ENV_VAR}")));
        assert!(!leaked_in(&format!(
            "{PREFIX}00000000000000000000000000000000"
        )));
        assert!(leaked_in(&format!("{ENV_VAR}={}", value())));
    }
}
