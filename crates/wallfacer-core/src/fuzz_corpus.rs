//! Phase R — persistent fuzz corpus.
//!
//! The original `fuzz` plan was stateless: every iteration
//! generates a payload from the schema seeded by the master seed,
//! invokes the tool, records findings, throws the input away.
//! That's good for reproducibility but it means `wallfacer fuzz`
//! repeated against the same server, the same seed, the same
//! pack, finds the same bugs over and over and never explores
//! beyond what one fresh schema-driven generator can synthesise.
//!
//! Phase R adds a persistent input corpus on top, in the spirit
//! of libFuzzer / AFL's coverage-feedback loop:
//!
//! 1. Inputs that triggered a finding are saved.
//! 2. Inputs that produced a previously-unseen *response
//!    fingerprint* are saved (proxy for "explored a new path").
//! 3. Subsequent runs read the corpus, pick a random entry, and
//!    mutate it — by default 90 % of the time. The remaining 10 %
//!    is pure schema-driven random, so a fuzzer that has converged
//!    on a small basin keeps exploring.
//!
//! The corpus lives at `<corpus_dir>/../fuzz_corpus/<tool>/`
//! (sibling of the findings corpus), one JSON file per entry,
//! filename keyed on a SHA-256 of the canonical input. Entries are
//! deduplicated on the input itself so identical mutations don't
//! grow the corpus indefinitely.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::corpus::sanitize_tool_name;

/// One persisted entry in the fuzz corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCorpusEntry {
    /// Tool the entry targets. Mirrors the per-tool subdirectory
    /// it lives in.
    pub tool: String,
    /// Concrete input payload that survived. Re-used as the seed
    /// of future mutation rounds.
    pub input: Value,
    /// Why this entry was kept — either it triggered a finding
    /// (the strongest signal) or it produced a never-before-seen
    /// response fingerprint.
    pub trigger: CorpusTrigger,
    /// Response fingerprint at the time of capture; persisted so
    /// the dedup tracker can be rebuilt by replaying the corpus
    /// on startup.
    pub fingerprint: String,
    /// When the entry was captured. Older corpus entries are
    /// preferred when picking a mutation seed (they've had more
    /// chances to be useful), but the picker is still random.
    pub timestamp: DateTime<Utc>,
}

/// Why an input is interesting enough to keep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CorpusTrigger {
    /// The input triggered a [`crate::finding::Finding`]. The
    /// strongest signal — these are the entries that produced
    /// real bugs and are worth mutating from again.
    Finding {
        /// Lower-snake-case identifier of the finding kind.
        kind: String,
    },
    /// The input produced a previously-unseen response
    /// fingerprint. Soft signal: useful for exploration, but the
    /// fingerprint hashing scheme is conservative so most novelty
    /// caught here is shallow ("server returned a slightly
    /// different error message").
    NewFingerprint,
}

#[derive(Debug, Error)]
pub enum FuzzCorpusError {
    #[error("create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("serialise corpus entry: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, FuzzCorpusError>;

/// Persistent fuzz-input store. Cheaply `Clone`-able; the on-disk
/// layout is the source of truth, in-memory state is just a cache
/// for fingerprint dedup during a single run.
#[derive(Debug, Clone)]
pub struct FuzzCorpus {
    root: PathBuf,
}

impl FuzzCorpus {
    /// Builds a corpus rooted at `root`. The directory is created
    /// lazily on the first `save` — operators that don't enable
    /// the corpus pay zero filesystem cost.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Path on disk for `tool`'s sub-corpus. Sanitised against
    /// untrusted tool names per the same rules as the findings
    /// corpus (Phase v0.3.2).
    pub fn tool_dir(&self, tool: &str) -> PathBuf {
        self.root.join(sanitize_tool_name(tool))
    }

    /// Reads every persisted entry for `tool`. Returns an empty
    /// vector when the directory doesn't exist yet (a fresh
    /// run-against-new-server).
    pub fn list(&self, tool: &str) -> Result<Vec<FuzzCorpusEntry>> {
        let dir = self.tool_dir(tool);
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|source| FuzzCorpusError::Read {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| FuzzCorpusError::Read {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let bytes = fs::read(&path).map_err(|source| FuzzCorpusError::Read {
                    path: path.clone(),
                    source,
                })?;
                if let Ok(parsed) = serde_json::from_slice::<FuzzCorpusEntry>(&bytes) {
                    out.push(parsed);
                }
            }
        }
        out.sort_by_key(|e| e.timestamp);
        Ok(out)
    }

    /// Saves `entry`. Writes are idempotent — keying on a SHA-256
    /// of the input means identical inputs don't grow the corpus,
    /// even when called concurrently.
    pub fn save(&self, entry: &FuzzCorpusEntry) -> Result<PathBuf> {
        let dir = self.tool_dir(&entry.tool);
        fs::create_dir_all(&dir).map_err(|source| FuzzCorpusError::CreateDir {
            path: dir.clone(),
            source,
        })?;
        let key = input_key(&entry.input);
        let path = dir.join(format!("{key}.json"));
        let body = serde_json::to_vec_pretty(entry)?;
        // Use create_new on first write but tolerate a pre-existing
        // file from a concurrent or prior run — the key dedup means
        // the body would be identical.
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|source| FuzzCorpusError::Write {
                path: path.clone(),
                source,
            })?;
        file.write_all(&body)
            .map_err(|source| FuzzCorpusError::Write {
                path: path.clone(),
                source,
            })?;
        Ok(path)
    }

    /// Total number of entries across every tool sub-corpus.
    /// Used by tests + the human reporter ("corpus: N entries").
    pub fn total(&self) -> Result<usize> {
        if !self.root.is_dir() {
            return Ok(0);
        }
        let mut total = 0;
        for entry in fs::read_dir(&self.root).map_err(|source| FuzzCorpusError::Read {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| FuzzCorpusError::Read {
                path: self.root.clone(),
                source,
            })?;
            if entry.path().is_dir() {
                let count = fs::read_dir(entry.path())
                    .map(|i| {
                        i.flatten()
                            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                            .count()
                    })
                    .unwrap_or(0);
                total += count;
            }
        }
        Ok(total)
    }
}

/// SHA-256 of the canonical JSON of `input`, hex-encoded — used
/// as the on-disk filename so identical mutations dedup naturally.
pub fn input_key(input: &Value) -> String {
    let canonical = crate::finding::canonical_json(input);
    let hash = Sha256::digest(canonical.as_bytes());
    hex::encode(hash)[..16].to_string()
}

/// Conservative response fingerprint. Hashes:
/// - `isError` boolean (or `null` when missing),
/// - the *type* of every entry in `content` (so a `text` →
///   `image` swap registers as a different shape),
/// - the first 64 bytes of `content[0].text` after Unicode
///   normalisation (catches "different error message" novelty).
///
/// Conservative on purpose: a too-fine fingerprint would flag
/// every mutation as novel and explode the corpus. The 64-byte
/// prefix gives us "this is a different class of response"
/// without "this is a different rendering of the same response".
pub fn response_fingerprint(response: &Value) -> String {
    let mut hasher = Sha256::new();
    let is_error = response.get("isError").and_then(Value::as_bool);
    hasher.update(format!("isError={is_error:?}|").as_bytes());
    if let Some(arr) = response.get("content").and_then(Value::as_array) {
        for item in arr {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or("?");
            hasher.update(format!("type={kind}|").as_bytes());
        }
        if let Some(first_text) = arr
            .first()
            .and_then(|v| v.get("text"))
            .and_then(Value::as_str)
        {
            let prefix: String = first_text.chars().take(64).collect();
            hasher.update(prefix.as_bytes());
        }
    }
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn entry(tool: &str, input: Value, trigger: CorpusTrigger) -> FuzzCorpusEntry {
        FuzzCorpusEntry {
            tool: tool.to_string(),
            fingerprint: response_fingerprint(
                &json!({"content": [{"type": "text", "text": "ok"}]}),
            ),
            input,
            trigger,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn save_then_list_round_trips() {
        let dir = tempdir().expect("tempdir");
        let corpus = FuzzCorpus::new(dir.path().to_path_buf());
        let e = entry(
            "x",
            json!({"a": 1}),
            CorpusTrigger::Finding {
                kind: "crash".to_string(),
            },
        );
        corpus.save(&e).expect("save");
        let listed = corpus.list("x").expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].input, json!({"a": 1}));
    }

    #[test]
    fn identical_inputs_dedup_on_disk() {
        let dir = tempdir().expect("tempdir");
        let corpus = FuzzCorpus::new(dir.path().to_path_buf());
        for _ in 0..3 {
            let e = entry(
                "x",
                json!({"a": 1, "b": "constant"}),
                CorpusTrigger::NewFingerprint,
            );
            corpus.save(&e).expect("save");
        }
        let listed = corpus.list("x").expect("list");
        assert_eq!(
            listed.len(),
            1,
            "identical inputs must dedup to a single file (key = SHA-256 of canonical JSON)"
        );
    }

    #[test]
    fn list_returns_empty_for_unknown_tool() {
        let dir = tempdir().expect("tempdir");
        let corpus = FuzzCorpus::new(dir.path().to_path_buf());
        assert!(corpus.list("never-saved").expect("list").is_empty());
    }

    #[test]
    fn fingerprint_changes_when_is_error_flips() {
        let a = response_fingerprint(&json!({"content": [], "isError": false}));
        let b = response_fingerprint(&json!({"content": [], "isError": true}));
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_changes_when_content_type_changes() {
        let a = response_fingerprint(&json!({"content": [{"type": "text", "text": "x"}]}));
        let b = response_fingerprint(&json!({"content": [{"type": "image", "data": "x"}]}));
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_stable_for_same_response() {
        let r = json!({"content": [{"type": "text", "text": "foo"}], "isError": false});
        assert_eq!(response_fingerprint(&r), response_fingerprint(&r));
    }

    #[test]
    fn fingerprint_first_text_prefix_separates_distinct_messages() {
        let a = response_fingerprint(
            &json!({"content": [{"type": "text", "text": "permission denied"}]}),
        );
        let b = response_fingerprint(&json!({"content": [{"type": "text", "text": "not found"}]}));
        assert_ne!(a, b);
    }

    #[test]
    fn total_counts_across_tool_subdirs() {
        let dir = tempdir().expect("tempdir");
        let corpus = FuzzCorpus::new(dir.path().to_path_buf());
        corpus
            .save(&entry("x", json!({"a": 1}), CorpusTrigger::NewFingerprint))
            .unwrap();
        corpus
            .save(&entry("y", json!({"b": 2}), CorpusTrigger::NewFingerprint))
            .unwrap();
        corpus
            .save(&entry("y", json!({"b": 3}), CorpusTrigger::NewFingerprint))
            .unwrap();
        assert_eq!(corpus.total().unwrap(), 3);
    }
}
