//! Reproducible seed derivation.
//!
//! Phase E5 introduces a 256-bit canonical seed and switches the RNG used
//! by every plan to `ChaCha20Rng`. The previous truncated-to-`u64` form is
//! kept (deprecated) so corpus files persisted by v0.1 continue to display
//! a stable seed in `repro.seed`.
//!
//! # Reproducibility contract
//!
//! Given a finding with `repro.seed`, `repro.tool_call`, and the master
//! seed used during the original run, replay is exact iff the plan re-runs
//! the same code path (same generation mode, same `tool` name, same
//! `iteration` index). The recipe:
//!
//! ```text
//! seed_bytes = SHA-256(
//!     master_seed.to_le_bytes()  // 8 bytes
//!     ‖ tool.as_bytes()          // tool name verbatim
//!     ‖ iteration.to_le_bytes()  // 8 bytes
//! )                                // 32-byte digest
//! rng = ChaCha20Rng::from_seed(seed_bytes)
//! ```
//!
//! `repro.seed` (a `u64`) is the first 8 bytes of `seed_bytes`, kept for
//! human-readable filenames and debugging. The full 32-byte seed is
//! re-derivable from the recipe components, which are all stored on the
//! finding (master_seed is the run-level master + the tool name + the
//! iteration index encoded inside `repro.tool_call`'s wrapping report).

use sha2::{Digest, Sha256};

/// Returns the canonical 256-bit seed for a `(master, tool, iteration)`
/// triple. Stable across runs and platforms: identical inputs always
/// yield identical output bytes.
pub fn derive_seed_canonical(master_seed: u64, tool: &str, iteration: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_seed.to_le_bytes());
    hasher.update(tool.as_bytes());
    hasher.update(iteration.to_le_bytes());
    hasher.finalize().into()
}

/// Truncated 64-bit form of [`derive_seed_canonical`], retained for the
/// human-facing `repro.seed` field on every finding. Future versions that
/// store the full 32-byte seed in the corpus may remove this helper.
pub fn derive_seed(master_seed: u64, tool: &str, iteration: u64) -> u64 {
    let canonical = derive_seed_canonical(master_seed, tool, iteration);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&canonical[..8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn canonical_seed_is_deterministic() {
        let a = derive_seed_canonical(42, "echo", 7);
        let b = derive_seed_canonical(42, "echo", 7);
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_seed_is_input_sensitive() {
        let base = derive_seed_canonical(42, "echo", 0);
        assert_ne!(derive_seed_canonical(42, "echo", 1), base);
        assert_ne!(derive_seed_canonical(42, "different", 0), base);
        assert_ne!(derive_seed_canonical(43, "echo", 0), base);
    }

    #[test]
    fn truncated_seed_matches_first_eight_bytes() {
        let canonical = derive_seed_canonical(123, "tool", 4);
        let truncated = derive_seed(123, "tool", 4);
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&canonical[..8]);
        assert_eq!(truncated, u64::from_le_bytes(expected));
    }
}
