use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::finding::Finding;

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
}

impl Corpus {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
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

        let _lock = CorpusLock::acquire(wallfacer_dir.join(".lock"))?;

        let tool_dir = self.root.join(&finding.tool);
        fs::create_dir_all(&tool_dir).map_err(|source| CorpusError::CreateDir {
            path: tool_dir.clone(),
            source,
        })?;

        let path = tool_dir.join(format!("{}.json", finding.id));
        let body =
            serde_json::to_string_pretty(finding).map_err(|source| CorpusError::Serialize {
                id: finding.id.clone(),
                source,
            })?;
        fs::write(&path, body).map_err(|source| CorpusError::Write {
            path: path.clone(),
            source,
        })?;
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

impl CorpusLock {
    fn acquire(path: PathBuf) -> Result<Self> {
        let start = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if start.elapsed() >= Duration::from_secs(5) {
                        return Err(CorpusError::LockTimeout(path));
                    }
                    thread::sleep(Duration::from_millis(50));
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
