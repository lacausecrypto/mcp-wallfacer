//! Tool-name filtering using [`globset`].
//!
//! Phase C4: replaces the home-grown `*`-only matcher with a real glob
//! engine that supports `**`, `?`, `[abc]`, and brace expansion (`{a,b}`).
//! The crate's `Glob` is built once and reused across iterations.

use globset::{Glob, GlobMatcher};
use thiserror::Error;

/// Errors raised when a glob pattern fails to compile.
#[derive(Debug, Error)]
pub enum GlobError {
    /// The pattern is not a syntactically valid glob.
    #[error("invalid glob pattern `{pattern}`: {source}")]
    Invalid {
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

/// Match a tool name against include/exclude patterns. An empty `includes`
/// list matches everything; otherwise the name must match at least one
/// include pattern. Names matching any exclude pattern are dropped.
pub fn matches_filters(name: &str, includes: &[String], excludes: &[String]) -> bool {
    let included = includes.is_empty() || includes.iter().any(|pattern| match_one(pattern, name));
    let excluded = excludes.iter().any(|pattern| match_one(pattern, name));
    included && !excluded
}

/// Compile a single glob pattern. Surfaces compile errors so callers can
/// reject bad config early instead of silently failing a match.
pub fn compile(pattern: &str) -> Result<GlobMatcher, GlobError> {
    Glob::new(pattern)
        .map(|glob| glob.compile_matcher())
        .map_err(|source| GlobError::Invalid {
            pattern: pattern.to_string(),
            source,
        })
}

fn match_one(pattern: &str, text: &str) -> bool {
    // Compile-on-call: cheap for the size of patterns we accept and avoids
    // exposing `GlobMatcher` in the public API for now. Plans build their
    // own caches when filtering long lists of tools.
    Glob::new(pattern)
        .map(|glob| glob.compile_matcher().is_match(text))
        .unwrap_or(false)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn star_matches_segment() {
        assert!(match_one("foo*", "foobar"));
        assert!(match_one("*bar", "foobar"));
        assert!(match_one("foo*bar", "foozbar"));
    }

    #[test]
    fn double_star_matches_path() {
        assert!(match_one("**/foo", "a/b/c/foo"));
        assert!(match_one("**/foo", "foo"));
    }

    #[test]
    fn brace_expansion() {
        assert!(match_one("tools.{a,b}", "tools.a"));
        assert!(match_one("tools.{a,b}", "tools.b"));
        assert!(!match_one("tools.{a,b}", "tools.c"));
    }

    #[test]
    fn char_class() {
        assert!(match_one("v[123]", "v2"));
        assert!(!match_one("v[123]", "v9"));
    }

    #[test]
    fn includes_and_excludes_combine() {
        let includes = vec!["read_*".to_string()];
        let excludes = vec!["read_secret".to_string()];
        assert!(matches_filters("read_users", &includes, &excludes));
        assert!(!matches_filters("read_secret", &includes, &excludes));
        assert!(!matches_filters("write_users", &includes, &excludes));
    }

    #[test]
    fn empty_includes_match_everything() {
        assert!(matches_filters("any.tool", &[], &[]));
    }

    #[test]
    fn invalid_pattern_does_not_match() {
        // `[unterminated` is not a valid glob.
        assert!(!match_one("[unterminated", "anything"));
    }
}
