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
    #[error(
        "config {path} references env var `{name}` that is not set; \
         export it before running, or escape `$` as `$$` to keep the literal"
    )]
    MissingEnv { path: PathBuf, name: String },
    #[error("config {path} contains malformed `${{...}}` placeholder near `{snippet}`")]
    MalformedPlaceholder { path: PathBuf, snippet: String },
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

/// `[destructive]` section of `wallfacer.toml`. By default user
/// `patterns` are layered on top of the built-in keyword list (`delete`,
/// `drop`, ...). Set `replace_defaults = true` to opt out of the
/// built-ins entirely.
///
/// ```toml
/// [destructive]
/// patterns = ["^remove_.*$", "^drop_.*$"]
/// # replace_defaults = true   # uncomment to disable built-ins
/// ```
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DestructiveConfig {
    /// Regex patterns matched against tool names. Layered on top of the
    /// built-in keyword detector unless [`Self::replace_defaults`] is
    /// set.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// When `true`, the default keyword detector is disabled and only
    /// [`Self::patterns`] decides which tools are destructive.
    ///
    /// Default `false` is additive: an operator who adds one custom
    /// pattern still gets the protection from the built-in keywords
    /// like `delete`, `drop`, `destroy`, ...
    #[serde(default)]
    pub replace_defaults: bool,
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

impl SeverityConfig {
    /// Looks up an override severity for `keyword` (e.g. `"crash"`,
    /// `"hang"`, `"protocol_error"`, ...). Returns `None` when no
    /// override is configured or the configured value isn't a recognised
    /// severity name. Plans use this to override
    /// `FindingKind::default_severity()` before persisting a finding.
    pub fn resolve(&self, keyword: &str) -> Option<crate::finding::Severity> {
        let raw = self.overrides.get(keyword)?;
        match raw.to_ascii_lowercase().as_str() {
            "low" => Some(crate::finding::Severity::Low),
            "medium" => Some(crate::finding::Severity::Medium),
            "high" => Some(crate::finding::Severity::High),
            "critical" => Some(crate::finding::Severity::Critical),
            _ => None,
        }
    }
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
        let expanded = expand_env(&source, path, &|name| env::var(name).ok())?;
        toml::from_str(&expanded).map_err(|source| TargetError::Parse {
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

/// Expands `${NAME}` placeholders against `lookup` and lets `$$` escape a
/// literal `$`. A bare `$` followed by anything other than `$` or `{` is
/// passed through as-is, so existing configs that legitimately contain `$`
/// (e.g. shell-style command lines) keep working unchanged.
///
/// This runs *before* TOML parsing on the raw file source, which means the
/// substitution sees both string values and key/section names. The lookup
/// is a function so tests can avoid touching the real environment.
fn expand_env(
    source: &str,
    path: &Path,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }
        match chars.peek().map(|(_, next)| *next) {
            Some('$') => {
                // `$$` → literal `$`.
                out.push('$');
                chars.next();
            }
            Some('{') => {
                chars.next(); // consume `{`
                let mut name = String::new();
                let mut closed = false;
                for (_, c) in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    name.push(c);
                }
                if !closed || name.is_empty() {
                    let snippet = source[idx..(idx + 8).min(source.len())].to_string();
                    return Err(TargetError::MalformedPlaceholder {
                        path: path.to_path_buf(),
                        snippet,
                    });
                }
                match lookup(&name) {
                    Some(value) => out.push_str(&value),
                    None => {
                        return Err(TargetError::MissingEnv {
                            path: path.to_path_buf(),
                            name,
                        });
                    }
                }
            }
            _ => {
                // Bare `$` — leave alone.
                out.push('$');
            }
        }
    }
    Ok(out)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(
        map: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| map.get(name).map(|v| (*v).to_string())
    }

    #[test]
    fn expands_braced_placeholder() {
        let env = HashMap::from([("WALLFACER_BEARER", "abc123")]);
        let out = expand_env(
            r#"Authorization = "Bearer ${WALLFACER_BEARER}""#,
            Path::new("/x"),
            &lookup(&env),
        )
        .unwrap();
        assert_eq!(out, r#"Authorization = "Bearer abc123""#);
    }

    #[test]
    fn double_dollar_escapes_to_literal() {
        let env = HashMap::new();
        let out = expand_env("price = \"$$50\"", Path::new("/x"), &lookup(&env)).unwrap();
        assert_eq!(out, "price = \"$50\"");
    }

    #[test]
    fn bare_dollar_passes_through() {
        let env = HashMap::new();
        let out = expand_env(r#"command = "echo $HOME""#, Path::new("/x"), &lookup(&env)).unwrap();
        assert_eq!(out, r#"command = "echo $HOME""#);
    }

    #[test]
    fn missing_env_var_surfaces_error() {
        let env = HashMap::new();
        let err = expand_env(
            r#"Authorization = "Bearer ${WALLFACER_BEARER}""#,
            Path::new("/x"),
            &lookup(&env),
        )
        .unwrap_err();
        match err {
            TargetError::MissingEnv { name, .. } => assert_eq!(name, "WALLFACER_BEARER"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn malformed_placeholder_is_rejected() {
        let env = HashMap::new();
        let err = expand_env(r#"x = "${unterminated"#, Path::new("/x"), &lookup(&env)).unwrap_err();
        assert!(matches!(err, TargetError::MalformedPlaceholder { .. }));
        let err = expand_env(r#"x = "${}""#, Path::new("/x"), &lookup(&env)).unwrap_err();
        assert!(matches!(err, TargetError::MalformedPlaceholder { .. }));
    }
}
