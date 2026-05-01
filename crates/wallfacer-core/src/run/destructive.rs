//! Destructive-tool detection.
//!
//! Phase C5 layers three signals, in order:
//!
//! 1. **MCP annotations.** If the server declares
//!    `tool.annotations.destructive_hint == Some(true)` and does not also
//!    set `read_only_hint == Some(true)`, the tool is destructive.
//! 2. **Configurable patterns.** Operators can declare additional
//!    destructive name patterns in `wallfacer.toml`:
//!
//!    ```toml
//!    [destructive]
//!    patterns = ["^remove_.*$", "^drop_.*$"]
//!    ```
//!
//!    When `patterns` is empty, a default keyword list is used: `delete`,
//!    `drop`, `destroy`, `truncate`, `kill`, `wipe`, `purge`, `reset`.
//! 3. **Allowlist (regex).** `[allow_destructive] tools` is now a list of
//!    regular expressions. A matching tool is permitted to be fuzzed even
//!    when classified destructive.
//!
//! ```toml
//! [allow_destructive]
//! tools = ["^logs_.*$"]   # keep "logs_delete_old" in the fuzz set
//! ```

use regex::Regex;
use rmcp::model::Tool;
use thiserror::Error;

use crate::target::{AllowDestructiveConfig, DestructiveConfig};

/// Result of classifying a single tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolClassification {
    /// Tool is safe to fuzz.
    Allowed,
    /// Tool is destructive and not in the allowlist.
    Destructive {
        /// Why the tool was classified destructive.
        reason: String,
    },
    /// Tool is destructive but matches the allowlist; fuzzing is permitted.
    DestructiveButAllowed {
        /// Why the tool was classified destructive.
        reason: String,
    },
}

impl ToolClassification {
    /// Returns `true` if the classification means the tool is currently
    /// safe to invoke.
    pub fn is_runnable(&self) -> bool {
        matches!(
            self,
            ToolClassification::Allowed | ToolClassification::DestructiveButAllowed { .. }
        )
    }

    /// Returns the destructive reason, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            ToolClassification::Destructive { reason }
            | ToolClassification::DestructiveButAllowed { reason } => Some(reason),
            ToolClassification::Allowed => None,
        }
    }
}

/// Errors raised when configuration patterns fail to compile.
#[derive(Debug, Error)]
pub enum DestructiveError {
    /// A regex in `[destructive] patterns` or `[allow_destructive] tools`
    /// did not compile.
    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Compiled detector reused across tool classifications.
#[derive(Debug)]
pub struct DestructiveDetector {
    destructive_patterns: Vec<Regex>,
    allow_patterns: Vec<Regex>,
    use_default_keywords: bool,
}

const DEFAULT_KEYWORDS: &[&str] = &[
    "delete", "drop", "destroy", "truncate", "kill", "wipe", "purge", "reset",
];

impl DestructiveDetector {
    /// Compiles a detector from configuration. Returns an error if any
    /// pattern fails to parse.
    ///
    /// Default keywords (`delete`, `drop`, ...) stay active unless the
    /// operator opts out via `[destructive] replace_defaults = true`.
    /// Older configs that simply added `patterns` used to silently lose
    /// the built-in protection — that footgun is gone.
    pub fn from_config(
        destructive: &DestructiveConfig,
        allow: &AllowDestructiveConfig,
    ) -> Result<Self, DestructiveError> {
        let destructive_patterns = compile_all(&destructive.patterns)?;
        let allow_patterns = compile_all(&allow.tools)?;
        Ok(Self {
            destructive_patterns,
            allow_patterns,
            use_default_keywords: !destructive.replace_defaults,
        })
    }

    /// Classifies a single tool.
    pub fn classify(&self, tool: &Tool) -> ToolClassification {
        let name = tool.name.as_ref();
        let description = tool.description.as_deref();
        let annotations_says_destructive = tool
            .annotations
            .as_ref()
            .is_some_and(|a| a.destructive_hint == Some(true) && a.read_only_hint != Some(true));
        let annotations_says_read_only = tool
            .annotations
            .as_ref()
            .is_some_and(|a| a.read_only_hint == Some(true));

        if annotations_says_read_only {
            return ToolClassification::Allowed;
        }

        let reason = if annotations_says_destructive {
            Some("annotations.destructive_hint == true".to_string())
        } else if let Some(pattern) = self.match_destructive_pattern(name) {
            Some(format!("name matches destructive pattern `{pattern}`"))
        } else {
            self.match_default_keyword(name, description)
                .map(|keyword| format!("name/description contains keyword `{keyword}`"))
        };

        match reason {
            None => ToolClassification::Allowed,
            Some(reason) => {
                if self.allow_patterns.iter().any(|r| r.is_match(name)) {
                    ToolClassification::DestructiveButAllowed { reason }
                } else {
                    ToolClassification::Destructive { reason }
                }
            }
        }
    }

    fn match_destructive_pattern(&self, name: &str) -> Option<String> {
        self.destructive_patterns
            .iter()
            .find(|r| r.is_match(name))
            .map(|r| r.as_str().to_string())
    }

    fn match_default_keyword(&self, name: &str, description: Option<&str>) -> Option<String> {
        if !self.use_default_keywords {
            return None;
        }
        let mut text = name.to_lowercase();
        if let Some(description) = description {
            text.push(' ');
            text.push_str(&description.to_lowercase());
        }
        // Split on every non-alphanumeric (including underscores) so we
        // catch keywords inside snake_case names like `logs_delete_old`.
        for keyword in DEFAULT_KEYWORDS {
            for word in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
                if word.starts_with(keyword) {
                    return Some((*keyword).to_string());
                }
            }
        }
        None
    }
}

fn compile_all(patterns: &[String]) -> Result<Vec<Regex>, DestructiveError> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|source| DestructiveError::InvalidRegex {
                pattern: pattern.clone(),
                source,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use rmcp::model::{Tool, ToolAnnotations};
    use std::sync::Arc;

    fn tool(name: &str, description: Option<&str>, annotations: Option<ToolAnnotations>) -> Tool {
        let description = description.unwrap_or("test tool").to_string();
        let mut tool = Tool::new(
            name.to_string(),
            description,
            Arc::new(serde_json::Map::new()),
        );
        if let Some(annotations) = annotations {
            tool = tool.annotate(annotations);
        }
        tool
    }

    fn empty_detector() -> DestructiveDetector {
        DestructiveDetector::from_config(
            &DestructiveConfig::default(),
            &AllowDestructiveConfig::default(),
        )
        .expect("default config compiles")
    }

    #[test]
    fn read_only_annotation_overrides_keywords() {
        let detector = empty_detector();
        let mut annotations = ToolAnnotations::default();
        annotations.read_only_hint = Some(true);
        let tool = tool("delete_user", None, Some(annotations));
        assert_eq!(detector.classify(&tool), ToolClassification::Allowed);
    }

    #[test]
    fn destructive_annotation_marks_tool_destructive() {
        let detector = empty_detector();
        let mut annotations = ToolAnnotations::default();
        annotations.destructive_hint = Some(true);
        let tool = tool("benign_name", None, Some(annotations));
        let classification = detector.classify(&tool);
        assert!(
            matches!(classification, ToolClassification::Destructive { .. }),
            "got {classification:?}"
        );
    }

    #[test]
    fn default_keywords_match_in_name() {
        let detector = empty_detector();
        let tool = tool("delete_user", None, None);
        assert!(matches!(
            detector.classify(&tool),
            ToolClassification::Destructive { .. }
        ));
    }

    #[test]
    fn allowlist_regex_unblocks_destructive_tool() {
        let allow = AllowDestructiveConfig {
            tools: vec!["^logs_.*$".to_string()],
        };
        let detector =
            DestructiveDetector::from_config(&DestructiveConfig::default(), &allow).unwrap();
        let tool = tool("logs_delete_old", None, None);
        let classification = detector.classify(&tool);
        assert!(
            matches!(
                classification,
                ToolClassification::DestructiveButAllowed { .. }
            ),
            "got {classification:?}"
        );
        assert!(classification.is_runnable());
    }

    #[test]
    fn custom_patterns_layer_on_top_of_default_keywords() {
        let destructive = DestructiveConfig {
            patterns: vec!["^remove_.*$".to_string()],
            replace_defaults: false,
        };
        let detector =
            DestructiveDetector::from_config(&destructive, &AllowDestructiveConfig::default())
                .unwrap();
        // Both the default keyword (`delete_user`) and the custom
        // pattern (`remove_*`) flag a tool as destructive: additive.
        let by_default_keyword = tool("delete_user", None, None);
        assert!(matches!(
            detector.classify(&by_default_keyword),
            ToolClassification::Destructive { .. }
        ));
        let by_custom_pattern = tool("remove_record", None, None);
        assert!(matches!(
            detector.classify(&by_custom_pattern),
            ToolClassification::Destructive { .. }
        ));
    }

    #[test]
    fn replace_defaults_disables_built_in_keywords() {
        let destructive = DestructiveConfig {
            patterns: vec!["^remove_.*$".to_string()],
            replace_defaults: true,
        };
        let detector =
            DestructiveDetector::from_config(&destructive, &AllowDestructiveConfig::default())
                .unwrap();
        let now_benign = tool("delete_user", None, None);
        assert_eq!(detector.classify(&now_benign), ToolClassification::Allowed);
        let still_destructive = tool("remove_record", None, None);
        assert!(matches!(
            detector.classify(&still_destructive),
            ToolClassification::Destructive { .. }
        ));
    }

    #[test]
    fn invalid_regex_surfaces_error() {
        let allow = AllowDestructiveConfig {
            tools: vec!["[unterminated".to_string()],
        };
        let result = DestructiveDetector::from_config(&DestructiveConfig::default(), &allow);
        assert!(result.is_err());
    }
}
