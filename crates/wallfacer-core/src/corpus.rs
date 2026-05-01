use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::{
    finding::Finding,
    redact::Redact,
    target::{default_lock_timeout_ms, OutputConfig},
};

#[derive(Debug, Error)]
pub enum CorpusError {
    #[error("failed to create corpus directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to acquire corpus lock {path}: {source}")]
    Lock { path: PathBuf, source: io::Error },
    #[error("timed out acquiring corpus lock {0}")]
    LockTimeout(PathBuf),
    #[error("failed to serialize finding {id}: {source}")]
    Serialize {
        id: String,
        source: serde_json::Error,
    },
    #[error("failed to write corpus file {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to read corpus file {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to parse corpus file {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("finding `{0}` not found in corpus")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, CorpusError>;

#[derive(Debug, Clone)]
pub struct Corpus {
    root: PathBuf,
    lock_timeout: Duration,
}

impl Corpus {
    /// Builds a corpus rooted at `root` with the default lock timeout.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            lock_timeout: Duration::from_millis(default_lock_timeout_ms()),
        }
    }

    /// Builds a corpus from a config, honoring `[output] lock_timeout_ms`.
    pub fn from_config(config: &OutputConfig) -> Self {
        Self {
            root: config.corpus_dir.clone(),
            lock_timeout: Duration::from_millis(config.lock_timeout_ms),
        }
    }

    /// Override the lock timeout (used by tests and CLI overrides).
    #[must_use]
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    pub fn write_finding(&self, finding: &Finding) -> Result<PathBuf> {
        let wallfacer_dir = self
            .root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".wallfacer"));
        fs::create_dir_all(&wallfacer_dir).map_err(|source| CorpusError::CreateDir {
            path: wallfacer_dir.clone(),
            source,
        })?;

        let _lock = CorpusLock::acquire(wallfacer_dir.join(".lock"), self.lock_timeout)?;

        // Tool names come from the MCP server, which we treat as
        // semi-trusted: a misbehaving server could declare a name like
        // `../../etc/x` and have us write outside `corpus_dir`. Sanitise
        // before joining so the path stays inside `self.root`.
        let safe_tool = sanitize_tool_name(&finding.tool);
        let tool_dir = self.root.join(&safe_tool);
        fs::create_dir_all(&tool_dir).map_err(|source| CorpusError::CreateDir {
            path: tool_dir.clone(),
            source,
        })?;

        // Persist the redacted form: corpus files may end up in CI artefacts,
        // shared storage, or commit history. The in-memory `finding` is
        // preserved untouched for callers that need the original payload (e.g.
        // an in-process replay).
        let redacted = finding.redacted();
        let path = tool_dir.join(format!("{}.json", redacted.id));
        let body =
            serde_json::to_string_pretty(&redacted).map_err(|source| CorpusError::Serialize {
                id: redacted.id.clone(),
                source,
            })?;
        write_secure(&path, body.as_bytes())?;
        Ok(path)
    }

    pub fn list_findings(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        if !self.root.is_dir() {
            return Ok(findings);
        }

        visit_json_files(&self.root, &mut |path| {
            findings.push(read_finding_file(path)?);
            Ok(())
        })?;
        findings.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(findings)
    }

    pub fn find_by_id(&self, id: &str) -> Result<Finding> {
        self.list_findings()?
            .into_iter()
            .find(|finding| finding.id == id || finding.id.starts_with(id))
            .ok_or_else(|| CorpusError::NotFound(id.to_string()))
    }
}

/// Writes a corpus file with restrictive permissions on Unix (mode `0o600`),
/// so the file is readable only by the owning user. On Windows, we fall back
/// to the default ACL inherited from the parent directory; operators sharing
/// runners should rely on directory-level permissions there. This is
/// documented in `docs/security.md` (Phase A).
fn write_secure(path: &Path, body: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| CorpusError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(body).map_err(|source| CorpusError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    // If the file pre-existed with looser permissions, `mode(0o600)` above
    // would not have applied. Tighten after the fact on Unix; best-effort.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn visit_json_files(path: &Path, visitor: &mut impl FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in fs::read_dir(path).map_err(|source| CorpusError::Read {
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| CorpusError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            visit_json_files(&path, visitor)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            visitor(&path)?;
        }
    }
    Ok(())
}

/// Returns a filesystem-safe form of a tool name: any character outside
/// `[A-Za-z0-9_-]` is replaced with `_`. Empty input maps to `_`.
///
/// The harness treats MCP server output as semi-trusted (the server is
/// what we are fuzzing), so tool names that flow into a filesystem path
/// must never contain `/`, `\`, `..`, or NUL bytes. This helper is the
/// single point of truth used by both the corpus and the inferred-schema
/// directory.
pub fn sanitize_tool_name(tool_name: &str) -> String {
    if tool_name.is_empty() {
        return "_".to_string();
    }
    tool_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn read_finding_file(path: &Path) -> Result<Finding> {
    let body = fs::read_to_string(path).map_err(|source| CorpusError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&body).map_err(|source| CorpusError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

struct CorpusLock {
    path: PathBuf,
}

const LOCK_BACKOFF_INITIAL: Duration = Duration::from_millis(25);
const LOCK_BACKOFF_CAP: Duration = Duration::from_millis(1_000);

impl CorpusLock {
    /// Tries to acquire the corpus lock, polling with exponential backoff
    /// (capped at [`LOCK_BACKOFF_CAP`]) until either the lock is held or
    /// `timeout` elapses. Phase E3 made the timeout configurable.
    fn acquire(path: PathBuf, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        let mut backoff = LOCK_BACKOFF_INITIAL;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        return Err(CorpusError::LockTimeout(path));
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let wait = backoff.min(remaining);
                    if wait.is_zero() {
                        return Err(CorpusError::LockTimeout(path));
                    }
                    thread::sleep(wait);
                    backoff = (backoff * 2).min(LOCK_BACKOFF_CAP);
                }
                Err(source) => {
                    return Err(CorpusError::Lock {
                        path: path.clone(),
                        source,
                    });
                }
            }
        }
    }
}

impl Drop for CorpusLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::finding::{FindingKind, ReproInfo};
    use serde_json::json;

    #[test]
    fn sanitize_strips_path_separators_and_traversal() {
        // 2× ".." + 2× "/" = 6 sanitised chars before "etc".
        assert_eq!(sanitize_tool_name("../../etc/passwd"), "______etc_passwd");
        assert_eq!(sanitize_tool_name("..\\windows"), "___windows");
        assert_eq!(sanitize_tool_name("ok_name-1"), "ok_name-1");
        assert_eq!(sanitize_tool_name(""), "_");
        assert_eq!(sanitize_tool_name("with space"), "with_space");
        assert_eq!(sanitize_tool_name("nul\0byte"), "nul_byte");
    }

    #[test]
    fn write_finding_keeps_output_inside_corpus_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("corpus");
        let corpus = Corpus::new(root.clone());
        let finding = Finding::new(
            FindingKind::Crash,
            "../../escape",
            "msg",
            "details",
            ReproInfo {
                seed: 0,
                tool_call: json!({}),
                transport: "stdio".to_string(),
                composition_trail: Vec::new(),
            },
        );
        let path = corpus.write_finding(&finding).unwrap();
        // Resolve via absolute paths to defeat any `..` segment that would
        // otherwise canonicalise outside the root.
        let canon_root = std::fs::canonicalize(&root).unwrap();
        let canon_path = std::fs::canonicalize(&path).unwrap();
        assert!(
            canon_path.starts_with(&canon_root),
            "finding written outside corpus root: {canon_path:?} not under {canon_root:?}"
        );
    }
}
