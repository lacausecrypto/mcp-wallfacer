//! Pack composition: parsing a primary YAML invariants file plus every
//! pack it `extends`, with cycle detection and a depth cap.
//!
//! Phase G isolates this from the CLI's pack lookup logic via the
//! [`PackLoader`] trait: the core knows how to chain
//! `parse_with_overrides` calls, while the CLI knows where the pack
//! YAML actually lives on disk (workspace `packs/` directory or, in
//! Phase H, embedded into the binary).
//!
//! Resolution order: every pack listed in `metadata.extends` (and
//! transitively) is loaded and its invariants are prepended to the
//! primary file's, so the primary file gets the last word when names
//! collide. Names are not auto-prefixed; packs are expected to namespace
//! their invariants themselves (e.g. `auth.unauthenticated_rejected`).

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::property::dsl::{parse_with_overrides, DslError, InvariantFile, MAX_EXTENDS_DEPTH};

/// Side of an error: was it the parser, or did the loader callback fail?
#[derive(Debug, Error)]
pub enum PackError {
    /// Couldn't fetch the source bytes for an `extends` entry.
    #[error("pack `{name}` could not be loaded: {message}")]
    Loader {
        /// Pack name as declared in `metadata.extends`.
        name: String,
        /// Loader-provided message.
        message: String,
    },
    /// One of the (transitive) pack files failed to parse or validate.
    #[error(transparent)]
    Dsl(#[from] DslError),
    /// Two packs reference each other directly or via an intermediate.
    #[error("cyclic `extends` chain: {0}")]
    Cycle(String),
    /// The chain of `extends` exceeded [`MAX_EXTENDS_DEPTH`].
    #[error("`extends` chain exceeded depth {MAX_EXTENDS_DEPTH}")]
    DepthExceeded,
}

/// Loader callback supplied by the caller. Returns the raw YAML source
/// for a pack referenced by name. CLI binds this to a workspace-relative
/// `packs/<name>.yaml` lookup; tests bind it to an in-memory map.
pub trait PackLoader {
    /// Returns the raw YAML source for the pack named `name` or a
    /// human-readable error message if it cannot be located.
    fn load(&self, name: &str) -> std::result::Result<String, String>;
}

impl<F> PackLoader for F
where
    F: Fn(&str) -> std::result::Result<String, String>,
{
    fn load(&self, name: &str) -> std::result::Result<String, String> {
        self(name)
    }
}

/// Parses `source` (the primary file) and recursively resolves every
/// `metadata.extends` reference, prepending the imported invariants to
/// the primary file's. The resulting [`InvariantFile`] carries the
/// primary file's `metadata` block; extended packs' metadata is
/// discarded after their invariants are pulled in.
///
/// `overrides` apply to **every** pack in the chain. Phase G keeps the
/// override scope global; per-pack overrides land in Phase H along with
/// the `wallfacer pack` commands.
pub fn resolve(
    source: &str,
    overrides: &BTreeMap<String, String>,
    loader: &dyn PackLoader,
) -> std::result::Result<InvariantFile, PackError> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    resolve_inner(source, overrides, loader, &mut visited, 0)
}

fn resolve_inner(
    source: &str,
    overrides: &BTreeMap<String, String>,
    loader: &dyn PackLoader,
    visited: &mut BTreeSet<String>,
    depth: usize,
) -> std::result::Result<InvariantFile, PackError> {
    if depth > MAX_EXTENDS_DEPTH {
        return Err(PackError::DepthExceeded);
    }
    let mut file = parse_with_overrides(source, overrides)?;

    // Snapshot the names this file extends, then drain them — the
    // resolved file no longer extends anything.
    let extends = file
        .metadata
        .as_mut()
        .map(|m| std::mem::take(&mut m.extends))
        .unwrap_or_default();

    if extends.is_empty() {
        return Ok(file);
    }

    let mut imported: Vec<crate::property::dsl::Invariant> = Vec::new();
    for parent_name in extends {
        if !visited.insert(parent_name.clone()) {
            return Err(PackError::Cycle(parent_name));
        }
        let parent_source = loader
            .load(&parent_name)
            .map_err(|message| PackError::Loader {
                name: parent_name.clone(),
                message,
            })?;
        let parent = resolve_inner(&parent_source, overrides, loader, visited, depth + 1)?;
        // Backtrack: the parent has been fully resolved, so it is no
        // longer "on the current path" for cycle detection purposes.
        visited.remove(&parent_name);
        imported.extend(parent.invariants);
    }

    // Imported first, primary last — primary overrides on collision.
    imported.append(&mut file.invariants);
    file.invariants = imported;
    Ok(file)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory loader for tests.
    struct MapLoader(HashMap<String, String>);
    impl PackLoader for MapLoader {
        fn load(&self, name: &str) -> std::result::Result<String, String> {
            self.0
                .get(name)
                .cloned()
                .ok_or_else(|| format!("unknown pack `{name}`"))
        }
    }

    fn loader(packs: &[(&str, &str)]) -> MapLoader {
        MapLoader(
            packs
                .iter()
                .map(|(name, source)| ((*name).to_string(), (*source).to_string()))
                .collect(),
        )
    }

    #[test]
    fn no_extends_passes_through() {
        let source = r#"
version: 3
metadata:
  name: solo
invariants:
  - name: t
    tool: echo
    fixed: {}
    assert:
      - kind: equals
        lhs: { value: 1 }
        rhs: { value: 1 }
"#;
        let file = resolve(source, &BTreeMap::new(), &loader(&[])).unwrap();
        assert_eq!(file.invariants.len(), 1);
    }

    #[test]
    fn extends_prepends_parent_invariants() {
        let parent = r#"
version: 3
metadata:
  name: parent
invariants:
  - name: parent.a
    tool: echo
    fixed: {}
    assert: []
"#;
        let child = r#"
version: 3
metadata:
  name: child
  extends: [parent]
invariants:
  - name: child.a
    tool: echo
    fixed: {}
    assert: []
"#;
        let file = resolve(child, &BTreeMap::new(), &loader(&[("parent", parent)])).unwrap();
        let names: Vec<_> = file.invariants.iter().map(|i| i.name.clone()).collect();
        assert_eq!(names, vec!["parent.a".to_string(), "child.a".to_string()]);
    }

    #[test]
    fn cycle_is_detected() {
        let a = r#"
version: 3
metadata:
  name: a
  extends: [b]
invariants: []
"#;
        let b = r#"
version: 3
metadata:
  name: b
  extends: [a]
invariants: []
"#;
        let err = resolve(a, &BTreeMap::new(), &loader(&[("a", a), ("b", b)])).unwrap_err();
        assert!(matches!(err, PackError::Cycle(_)));
    }

    #[test]
    fn depth_cap_is_enforced() {
        // Build a 6-level chain: a -> b -> c -> d -> e -> f
        let chain: Vec<(String, String)> = (0..6)
            .map(|i| {
                let name = format!("p{i}");
                let next = if i == 5 {
                    String::new()
                } else {
                    format!("[p{}]", i + 1)
                };
                let source = format!(
                    "version: 3\nmetadata:\n  name: {name}\n  extends: {next}\ninvariants: []\n"
                );
                (name, source)
            })
            .collect();
        let pairs: Vec<(&str, &str)> = chain
            .iter()
            .map(|(name, src)| (name.as_str(), src.as_str()))
            .collect();
        let err = resolve(&chain[0].1, &BTreeMap::new(), &loader(&pairs)).unwrap_err();
        assert!(matches!(err, PackError::DepthExceeded));
    }

    #[test]
    fn loader_failure_surfaces() {
        let child = r#"
version: 3
metadata:
  name: child
  extends: [missing]
invariants: []
"#;
        let err = resolve(child, &BTreeMap::new(), &loader(&[])).unwrap_err();
        match err {
            PackError::Loader { name, .. } => assert_eq!(name, "missing"),
            other => panic!("expected loader error, got {other:?}"),
        }
    }
}
