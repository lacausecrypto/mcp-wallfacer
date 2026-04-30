use std::{
    collections::HashMap,
    env, fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("config file not found; run `wallfacer init` or pass `--config <path>`")]
    NotFound,
    #[error("failed to read config {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
}

pub type Result<T> = std::result::Result<T, TargetError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Transport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    #[serde(flatten)]
    pub transport: Transport,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: Target,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
    #[serde(default)]
    pub allow_destructive: AllowDestructiveConfig,
    #[serde(default)]
    pub destructive: DestructiveConfig,
    /// Per-pack template parameter overrides (Phase G).
    ///
    /// `[packs.<pack_name>] key = "value"` populates the resolution
    /// context that `parse_with_overrides` consumes when loading the
    /// pack named `<pack_name>`. CLI `--param` flags layer on top of
    /// these.
    #[serde(default)]
    pub packs: HashMap<String, HashMap<String, String>>,
}

/// `[destructive]` section of `wallfacer.toml`. Empty by default; populating
/// `patterns` replaces the built-in keyword list (`delete`, `drop`, ...).
///
/// ```toml
/// [destructive]
/// patterns = ["^remove_.*$", "^drop_.*$"]
/// ```
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DestructiveConfig {
    /// Regex patterns matched against tool names. When non-empty, the
    /// default keyword detector is disabled in favor of these patterns.
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_corpus_dir")]
    pub corpus_dir: PathBuf,
    /// Maximum time, in milliseconds, that a corpus writer waits for the
    /// shared `.wallfacer/.lock` before giving up. Phase E3 raised the
    /// default from a hardcoded 5 s to 30 s and made it configurable so
    /// massively-parallel CI matrices don't trip on slow filesystems.
    #[serde(default = "default_lock_timeout_ms")]
    pub lock_timeout_ms: u64,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            corpus_dir: default_corpus_dir(),
            lock_timeout_ms: default_lock_timeout_ms(),
        }
    }
}

/// Default value for [`OutputConfig::lock_timeout_ms`].
pub fn default_lock_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SeverityConfig {
    #[serde(flatten)]
    pub overrides: HashMap<String, String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AllowDestructiveConfig {
    #[serde(default)]
    pub tools: Vec<String>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(|source| TargetError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&source).map_err(|source| TargetError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    pub fn load_from_lookup(explicit: Option<&Path>) -> Result<(PathBuf, Self)> {
        let path = find_config(explicit)?;
        let config = Self::load(&path)?;
        Ok((path, config))
    }
}

impl Target {
    pub fn transport_name(&self) -> &'static str {
        match self.transport {
            Transport::Stdio { .. } => "stdio",
            Transport::Http { .. } => "http",
        }
    }
}

pub fn default_timeout_ms() -> u64 {
    5000
}

pub fn default_corpus_dir() -> PathBuf {
    PathBuf::from(".wallfacer/corpus")
}

pub fn find_config(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let cwd = env::current_dir().map_err(|source| TargetError::Read {
        path: PathBuf::from("."),
        source,
    })?;

    let direct = cwd.join("wallfacer.toml");
    if direct.is_file() {
        return Ok(direct);
    }

    let mut current = cwd.as_path();
    loop {
        let candidate = current.join("wallfacer.toml");
        if candidate.is_file() {
            return Ok(candidate);
        }

        if current.join(".git").is_dir() {
            break;
        }

        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    Err(TargetError::NotFound)
}
