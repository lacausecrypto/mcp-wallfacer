//! Phase Q — pack-coverage analyser.
//!
//! Static analysis of which (pack, tool) pairs *would* be exercised
//! by a given run, computed without actually invoking the server.
//!
//! The signal is computed from three sources:
//! - the parsed [`crate::property::dsl::InvariantFile`] of every
//!   pack the operator wants to consider (their `invariants`,
//!   `for_each_tool`, and `sequences` blocks),
//! - the live `client.list_tools()` result,
//! - the destructive classifier (so the matrix surfaces tools that
//!   would be skipped at runtime as a separate "blocked" cell
//!   rather than "not exercised").
//!
//! The output [`CoverageMatrix`] feeds the `wallfacer coverage` CLI,
//! the v0.5 HTML report, and a `--strict` CI gate that fails when
//! any tool falls into the `Uncovered` bucket.

use std::collections::{BTreeMap, BTreeSet};

use rmcp::model::Tool;
use serde::Serialize;

use crate::{
    property::dsl::{Assertion, InvariantFile, ToolMatch},
    run::{DestructiveDetector, ToolClassification},
};

/// Per-cell verdict for a `(tool, pack)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCell {
    /// At least one invariant or sequence in the pack would target
    /// this tool at runtime.
    Covered,
    /// The tool would be touched, but the destructive detector
    /// refuses to invoke it without an allowlist match.
    Blocked,
    /// No invariant in the pack targets this tool name and no
    /// `for_each_tool` filter matches its annotations / name. The
    /// tool is silently un-exercised by this pack.
    Uncovered,
}

/// Aggregate coverage view: one row per tool, one column per pack.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageMatrix {
    /// Tool names, in the order returned by `list_tools`.
    pub tools: Vec<String>,
    /// Pack names, in the order they were passed in.
    pub packs: Vec<String>,
    /// `cells[tool][pack]` — guaranteed to be present for every
    /// declared `(tool, pack)` pair.
    pub cells: BTreeMap<String, BTreeMap<String, CoverageCell>>,
    /// Tools that no pack covers. Equivalent to
    /// `tools.iter().filter(|t| every cell is Uncovered)`. Surfaced
    /// here for `--strict` exit-code logic.
    pub uncovered_tools: Vec<String>,
}

impl CoverageMatrix {
    /// Builds a matrix from the parsed packs and a live tool list.
    /// Each (pack_name, file) tuple is one entry of the result; the
    /// caller is responsible for resolving `extends` and applying
    /// parameter overrides before passing the file in.
    pub fn build(
        packs: &[(String, InvariantFile)],
        tools: &[Tool],
        detector: &DestructiveDetector,
    ) -> Self {
        let pack_names: Vec<String> = packs.iter().map(|(n, _)| n.clone()).collect();
        let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        let tool_index: BTreeMap<String, &Tool> =
            tools.iter().map(|t| (t.name.to_string(), t)).collect();

        let mut cells: BTreeMap<String, BTreeMap<String, CoverageCell>> = BTreeMap::new();
        for tool_name in &tool_names {
            cells.insert(tool_name.clone(), BTreeMap::new());
        }

        for (pack_name, file) in packs {
            // Walk every invariant + for_each_tool + sequence step
            // and collect the set of tool names this pack would
            // exercise for *this* live tool list.
            let exercised = collect_exercised_tools(file, tools);

            for tool_name in &tool_names {
                let cell = if !exercised.contains(tool_name) {
                    CoverageCell::Uncovered
                } else if let Some(tool) = tool_index.get(tool_name) {
                    if matches!(
                        detector.classify(tool),
                        ToolClassification::Destructive { .. }
                    ) {
                        CoverageCell::Blocked
                    } else {
                        CoverageCell::Covered
                    }
                } else {
                    CoverageCell::Uncovered
                };
                if let Some(row) = cells.get_mut(tool_name) {
                    row.insert(pack_name.clone(), cell);
                }
            }
        }

        let uncovered_tools = tool_names
            .iter()
            .filter(|tool| {
                cells
                    .get(*tool)
                    .map(|row| row.values().all(|c| matches!(c, CoverageCell::Uncovered)))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        Self {
            tools: tool_names,
            packs: pack_names,
            cells,
            uncovered_tools,
        }
    }

    /// Number of `(tool, pack)` cells that are `Covered`.
    pub fn covered_cells(&self) -> usize {
        self.cells
            .values()
            .map(|row| {
                row.values()
                    .filter(|c| matches!(c, CoverageCell::Covered))
                    .count()
            })
            .sum()
    }

    /// Total number of `(tool, pack)` cells.
    pub fn total_cells(&self) -> usize {
        self.cells.values().map(|row| row.len()).sum()
    }
}

/// Walks the pack's invariants + for_each_tool + sequences and
/// returns the set of live tool names that at least one of those
/// blocks would exercise.
fn collect_exercised_tools(file: &InvariantFile, tools: &[Tool]) -> BTreeSet<String> {
    let live_names: BTreeSet<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let mut out: BTreeSet<String> = BTreeSet::new();

    for invariant in &file.invariants {
        // A literal tool name. Only counts if it actually matches a
        // live tool — otherwise the property runner skips it (Phase
        // L missing-tool handling) and there's no real coverage.
        if live_names.contains(&invariant.tool) {
            out.insert(invariant.tool.clone());
        }
    }

    for block in &file.for_each_tool {
        // Compile the where-clause regexes once per block.
        let name_re = block
            .matches
            .name_matches
            .as_deref()
            .and_then(|p| regex::Regex::new(p).ok());
        let description_re = block
            .matches
            .description_matches
            .as_deref()
            .and_then(|p| regex::Regex::new(p).ok());
        for tool in tools {
            if matches_filter(
                &block.matches,
                tool,
                name_re.as_ref(),
                description_re.as_ref(),
            ) {
                out.insert(tool.name.to_string());
            }
        }
    }

    for sequence in &file.sequences {
        // A sequence "covers" every tool it would actually call. We
        // intentionally count the sequence as covering all of its
        // declared steps — a partial sequence (one step missing on
        // the target) doesn't get split into per-step credit because
        // the runner refuses to half-run it (Phase L pre-flight
        // check).
        let all_steps_present = sequence
            .steps
            .iter()
            .all(|step| live_names.contains(&step.call));
        if !all_steps_present {
            continue;
        }
        for step in &sequence.steps {
            out.insert(step.call.clone());
        }
    }

    // Walk inline `matches_schema` + `for_each` assertions inside
    // invariants for completeness — those don't bind to a tool name
    // directly so nothing extra to surface here, but we keep the
    // structure in case future DSL extensions add sources.
    let _: &dyn Fn(&[Assertion]) = &|_| {};

    out
}

fn matches_filter(
    filter: &ToolMatch,
    tool: &Tool,
    name_re: Option<&regex::Regex>,
    description_re: Option<&regex::Regex>,
) -> bool {
    filter.matches(tool, name_re, description_re)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        property::dsl::parse,
        target::{AllowDestructiveConfig, DestructiveConfig},
    };
    use rmcp::model::Tool;
    use std::sync::Arc;

    fn tool(name: &str) -> Tool {
        Tool::new(name.to_string(), "", Arc::new(serde_json::Map::new()))
    }

    fn pack(name: &str, source: &str) -> (String, InvariantFile) {
        (name.to_string(), parse(source).expect("parse"))
    }

    fn detector() -> DestructiveDetector {
        DestructiveDetector::from_config(
            &DestructiveConfig::default(),
            &AllowDestructiveConfig::default(),
        )
        .expect("detector")
    }

    #[test]
    fn invariant_targeting_a_live_tool_marks_cell_covered() {
        let p = pack(
            "tiny",
            r#"
version: 2
invariants:
  - name: foo
    tool: alpha
    fixed: {}
    assert:
      - kind: equals
        lhs: { path: "$.response.isError" }
        rhs: { value: false }
"#,
        );
        let tools = vec![tool("alpha"), tool("beta")];
        let m = CoverageMatrix::build(&[p], &tools, &detector());
        assert_eq!(m.cells["alpha"]["tiny"], CoverageCell::Covered);
        assert_eq!(m.cells["beta"]["tiny"], CoverageCell::Uncovered);
        assert_eq!(m.uncovered_tools, vec!["beta".to_string()]);
    }

    #[test]
    fn for_each_tool_block_with_no_filter_covers_every_tool() {
        let p = pack(
            "all-tools",
            r#"
version: 3
metadata:
  name: all-tools
invariants: []
for_each_tool:
  - name: "all.{{tool_name}}"
    apply:
      input: schema_valid
      assert:
        - kind: equals
          lhs: { path: "$.response.isError" }
          rhs: { value: false }
"#,
        );
        let tools = vec![tool("alpha"), tool("beta")];
        let m = CoverageMatrix::build(&[p], &tools, &detector());
        assert_eq!(m.cells["alpha"]["all-tools"], CoverageCell::Covered);
        assert_eq!(m.cells["beta"]["all-tools"], CoverageCell::Covered);
        assert!(m.uncovered_tools.is_empty());
    }

    #[test]
    fn sequence_with_missing_step_does_not_count_as_coverage() {
        let p = pack(
            "stateful-like",
            r#"
version: 3
metadata:
  name: stateful-like
invariants: []
sequences:
  - name: "test.create_then_read"
    steps:
      - call: create_thing
      - call: read_thing
"#,
        );
        let only_create = vec![tool("create_thing")];
        let m = CoverageMatrix::build(&[p], &only_create, &detector());
        // `read_thing` isn't in the live tool list, so the sequence
        // would refuse to run — neither tool counts as covered.
        assert_eq!(
            m.cells["create_thing"]["stateful-like"],
            CoverageCell::Uncovered
        );
    }

    #[test]
    fn coverage_summary_counts_covered_cells() {
        let p = pack(
            "single",
            r#"
version: 2
invariants:
  - name: foo
    tool: alpha
    fixed: {}
    assert:
      - kind: equals
        lhs: { path: "$.response.isError" }
        rhs: { value: false }
"#,
        );
        let tools = vec![tool("alpha"), tool("beta")];
        let m = CoverageMatrix::build(&[p], &tools, &detector());
        assert_eq!(m.covered_cells(), 1);
        assert_eq!(m.total_cells(), 2);
    }
}
