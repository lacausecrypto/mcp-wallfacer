//! YAML invariants DSL.
//!
//! Phase D introduces:
//!
//! * **Typed operands** — `equals: { lhs: { path: "$.x" }, rhs: { value: 42 } }`
//!   removes the legacy `starts_with('$')` heuristic. The legacy form
//!   (`lhs: "$.x"`) keeps working: a bare string starting with `$` is still
//!   resolved as a path, anything else is a literal.
//! * **Boolean combinators** — `all_of`, `any_of`, `not`.
//! * **`for_each`** — runs child assertions for every node matched by a
//!   wildcard JSONPath.
//! * **`matches_schema`** — validates the value at a path against an inline
//!   JSON Schema using `jsonschema 0.46`.
//! * **Versioning** — `version: 1` and `version: 2` are accepted by the
//!   same parser; v2 unlocks the new constructs above without changing how
//!   v1 files parse.
//!
//! Phase G adds:
//!
//! * **`version: 3`** with a `metadata` block: `name`, `description`,
//!   `authors`, `tags`, `parameters`, and `extends`.
//! * **Mustache-style templating** — every `{{var}}` in the file is
//!   resolved before YAML parsing using parameter defaults overridden by
//!   the caller. References to undeclared parameters error.
//! * **`extends`** — pack inheritance with cycle detection and a depth
//!   cap; resolution lives in `crate::run::pack` because it requires a
//!   loader closure.
//!
//! See `tests/fixtures/invariants/*.yaml` for working examples of each
//! construct.

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Highest invariant file version this build understands.
pub const MAX_VERSION: u64 = 3;

/// Maximum depth of a chain of `metadata.extends` references. The
/// resolver returns an error past this depth so a malformed pack ring
/// cannot lock the loader into an unbounded walk.
pub const MAX_EXTENDS_DEPTH: usize = 4;

#[derive(Debug, Error)]
pub enum DslError {
    /// YAML deserialization failed.
    #[error("failed to parse invariants YAML: {0}")]
    Parse(#[from] serde_yaml::Error),
    /// `generate` and `fixed` were both set or both omitted on the same
    /// invariant.
    #[error("invariant `{0}` must define exactly one of `generate` or `fixed`")]
    InvalidInputMode(String),
    /// File declared a `version` greater than [`MAX_VERSION`].
    #[error("invariants file declares unsupported version `{0}`; expected ≤ {MAX_VERSION}")]
    UnsupportedVersion(u64),
    /// A `{{var}}` reference targets a parameter that the file does not
    /// declare and the caller did not override.
    #[error("undefined template parameter(s): {0:?}")]
    UndefinedParameters(Vec<String>),
    /// The caller passed an override for a parameter the pack does not
    /// declare. We reject these to surface typos rather than silently
    /// ignoring them.
    #[error("override key `{0}` is not declared in metadata.parameters")]
    UnknownParameterOverride(String),
    /// `for_each_tool[*].where.{name,description}_matches` regex failed
    /// to compile.
    #[error("invalid `where` regex: {0}")]
    InvalidWhereRegex(String),
}

pub type Result<T> = std::result::Result<T, DslError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantFile {
    pub version: u64,
    /// Pack-style metadata (name, description, parameters, extends).
    /// Optional: a v1/v2 invariants file omits the block entirely.
    /// (Phase G — version 3 introduces this; older versions ignore it.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PackMetadata>,
    pub invariants: Vec<Invariant>,
    /// Phase I — schema-aware invariant templates. Each block is
    /// expanded against the live `client.list_tools()` result at run
    /// time, producing one concrete [`Invariant`] per matching tool.
    /// Default empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub for_each_tool: Vec<ForEachToolBlock>,
}

/// Phase I — `for_each_tool` directive: a tool-name-agnostic template
/// expanded at run time against the server's tool list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForEachToolBlock {
    /// Invariant name template. May contain `{{tool_name}}`, replaced
    /// at expansion time with the matched tool's name.
    pub name: String,
    /// Filter that decides which tools the template applies to. When
    /// omitted, the template applies to *every* tool the server
    /// declares — useful for envelope-shape invariants that don't care
    /// about specific annotations.
    #[serde(rename = "where", default)]
    pub matches: ToolMatch,
    /// Body of the generated invariant, minus `name` (provided by the
    /// block) and `tool` (auto-set to the matched tool's name).
    pub apply: ApplyTemplate,
}

/// Filter for [`ForEachToolBlock`]. Every set field is an AND condition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolMatch {
    /// Match on `tool.annotations` fields. Each set field requires the
    /// tool's annotation to equal the given value.
    #[serde(default, skip_serializing_if = "ToolAnnotationMatch::is_empty")]
    pub annotations: ToolAnnotationMatch,
    /// Regex applied to `tool.name`. Tools whose name does not match
    /// are skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_matches: Option<String>,
    /// Regex applied to `tool.description`. Tools without a description
    /// or whose description does not match are skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_matches: Option<String>,
}

/// Subset of MCP `ToolAnnotations` fields the filter understands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolAnnotationMatch {
    #[serde(
        default,
        rename = "readOnlyHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_hint: Option<bool>,
    #[serde(
        default,
        rename = "destructiveHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive_hint: Option<bool>,
    #[serde(
        default,
        rename = "idempotentHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent_hint: Option<bool>,
    #[serde(
        default,
        rename = "openWorldHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
}

impl ToolAnnotationMatch {
    /// `true` when no annotation constraint is set; used by the serde
    /// `skip_serializing_if`.
    pub fn is_empty(&self) -> bool {
        self.read_only_hint.is_none()
            && self.destructive_hint.is_none()
            && self.idempotent_hint.is_none()
            && self.open_world_hint.is_none()
    }
}

/// Body of a [`ForEachToolBlock`]. Mirrors [`Invariant`] minus `name`
/// and `tool` — those are supplied by the block at expansion time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyTemplate {
    /// Optional input strategy. When set, overrides `fixed` and
    /// `generate`. See [`InputMode`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<BTreeMap<String, ValueSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<u32>,
    #[serde(rename = "assert")]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_fixtures: Vec<TestFixture>,
}

/// Input strategy for a `for_each_tool` invariant. Resolves at run
/// time against the live tool list (the runner has access to each
/// tool's input schema and annotations).
///
/// The default behaviour (when `input` is omitted) is unchanged from
/// v0.3.0–v0.3.2: the runner uses `fixed:` if set, otherwise
/// `generate:`, otherwise an empty `{}` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    /// Generate a payload matching the live tool's input schema with
    /// [`crate::mutate::schema_gen::GenMode::Conform`]. Use when an
    /// invariant tests the *valid-input* contract of a tool: the
    /// pre-v0.3.3 default of `fixed: {}` would trigger schema-validation
    /// errors on tools with required parameters and mask real bugs.
    SchemaValid,
}

/// `metadata` block of a v3 invariants file. Acts as the pack header
/// when the file is loaded as a rule pack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackMetadata {
    /// Canonical pack name. When the file is referenced via
    /// `wallfacer property --pack <name>`, `<name>` should match this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// One-paragraph human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Author identities (free-form strings, e.g. `"wallfacer-core"`,
    /// `"alice@example.org"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    /// Tags for catalog grouping (e.g. `["security", "auth"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Declared parameters. Every `{{name}}` referenced in the file
    /// must be declared here; the value of `default` is substituted
    /// unless the caller passes an override via `parse_with_overrides`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, Parameter>,
    /// Names of other packs whose invariants are imported when this
    /// pack is loaded. Cycles are rejected; depth is capped by
    /// [`MAX_EXTENDS_DEPTH`]. Resolution lives in
    /// `crate::run::pack::resolve_extends`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extends: Vec<String>,
}

/// Declaration of a single template parameter inside `metadata.parameters`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    /// One-line operator-facing description, surfaced by
    /// `wallfacer pack params <name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Logical type (currently informational; the substituted value is
    /// always a string at the YAML source level).
    #[serde(default = "default_param_kind", rename = "type")]
    pub kind: ParamKind,
    /// Default value used when no override is supplied. Always
    /// stringified before substitution.
    pub default: Value,
}

fn default_param_kind() -> ParamKind {
    ParamKind::String
}

/// Logical type of a [`Parameter`]. Informational for now; the
/// substituted value is always inserted as a string at the YAML source
/// level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamKind {
    String,
    Integer,
    Number,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub tool: String,
    /// Input strategy. See [`InputMode`]. When `Some`, the runner
    /// derives the per-case input from the live tool's metadata
    /// instead of from `fixed`/`generate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<BTreeMap<String, ValueSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<u32>,
    #[serde(rename = "assert")]
    pub assertions: Vec<Assertion>,
    /// Phase H — inline test fixtures for `wallfacer pack test`. Each
    /// fixture provides a synthetic response (and optionally an
    /// overriding input) along with whether evaluating the invariant
    /// against it should `pass` or `fail`. The runner compares the
    /// observed outcome to `expect` and surfaces mismatches as test
    /// failures, gating CI on pack quality without needing a live MCP
    /// server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub test_fixtures: Vec<TestFixture>,
}

/// One scripted test case for an invariant: a synthetic response (and
/// optional input override) plus the expected outcome. Phase H —
/// consumed by `wallfacer pack test`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFixture {
    /// Free-form short label, surfaced in the `pack test` output table.
    pub name: String,
    /// Optional override for `$.input`. When omitted, the fixture
    /// uses the invariant's `fixed` block (or an empty object if both
    /// are absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    /// Synthetic response value used as `$.response` during evaluation.
    pub response: Value,
    /// Outcome the runner expects when evaluating the invariant against
    /// this fixture.
    pub expect: FixtureExpect,
}

/// Outcome enum for [`TestFixture::expect`]. `Pass` means the invariant
/// must succeed; `Fail` means the invariant must report an assertion
/// failure (a structural error like a bad path is treated as a third
/// category and surfaced as a test failure of its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FixtureExpect {
    /// Invariant evaluation must return `Ok(())`.
    Pass,
    /// Invariant evaluation must return `Err(RunnerError::Assertion(...))`.
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueSpec {
    #[serde(rename = "type")]
    pub kind: ValueKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<ValueSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_items: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
}

/// An operand of a comparison (`equals`, `not_equals`, `at_most`, ...).
///
/// Three forms are accepted, selected by structure:
///
/// 1. `{ path: "$..." }` — explicit JSONPath, resolved against the
///    `{input, response}` context.
/// 2. `{ value: <any> }` — explicit literal.
/// 3. Anything else — bare value. If it's a string starting with `$` we
///    resolve it as a path (legacy v1 behaviour); otherwise it is treated
///    as a literal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Operand {
    /// `{ path: "$..." }`
    Path {
        /// JSONPath expression (RFC 9535 syntax).
        path: String,
    },
    /// `{ value: <any> }`
    Literal {
        /// Verbatim value.
        value: Value,
    },
    /// Anything else: number, boolean, plain object, or string. Strings
    /// starting with `$` are resolved as JSONPath at runtime to preserve
    /// the v1 contract; everything else is treated as a literal.
    Direct(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Assertion {
    /// `lhs == rhs` after operand resolution.
    Equals { lhs: Operand, rhs: Operand },
    /// `lhs != rhs` after operand resolution.
    NotEquals { lhs: Operand, rhs: Operand },
    /// Numeric `path <= value`.
    AtMost { path: String, value: Operand },
    /// Numeric `path >= value`.
    AtLeast { path: String, value: Operand },
    /// `len(path) == value` (for arrays / strings).
    LengthEq { path: String, value: Operand },
    /// `len(path) <= value`.
    LengthAtMost { path: String, value: Operand },
    /// `len(path) >= value`.
    LengthAtLeast { path: String, value: Operand },
    /// Type check: the value at `path` has the expected JSON type.
    IsType {
        path: String,
        #[serde(rename = "type")]
        expected: JsonType,
    },
    /// String at `path` matches `pattern` (Rust regex).
    MatchesRegex { path: String, pattern: String },
    /// All child assertions must pass (D1).
    AllOf {
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// At least one child assertion must pass (D1).
    AnyOf {
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// The single child assertion must fail (D1).
    Not {
        /// The assertion that must NOT hold for this invariant to pass.
        assertion: Box<Assertion>,
    },
    /// For every node matched by the wildcard JSONPath, every child
    /// assertion must pass (D3). The current node is exposed as `$.item`
    /// inside the `assert` block; the original input/response remain
    /// accessible via `$.input` / `$.response`.
    ForEach {
        path: String,
        #[serde(rename = "assert")]
        assertions: Vec<Assertion>,
    },
    /// The value at `path` validates against the inline JSON Schema (D4).
    MatchesSchema {
        path: String,
        /// Inline JSON Schema. Compiled with `jsonschema::validator_for`
        /// at evaluation time.
        schema: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

/// Parses an invariants YAML document with no template overrides. v3
/// files use the `metadata.parameters` defaults verbatim; v1/v2 files
/// pass through unchanged.
pub fn parse(source: &str) -> Result<InvariantFile> {
    parse_with_overrides(source, &BTreeMap::new())
}

/// Parses an invariants YAML document, applying `{{var}}` substitution
/// before YAML parsing.
///
/// Resolution order for the substituted value:
///
/// 1. The caller's `overrides` map (typically built from `--param` CLI
///    flags or `[packs.<name>]` config tables).
/// 2. The `default` field of the matching entry under
///    `metadata.parameters`.
///
/// Every `{{var}}` reference must resolve to a declared parameter — a
/// missing declaration produces [`DslError::UndefinedParameters`]. An
/// override targeting an undeclared parameter likewise produces
/// [`DslError::UnknownParameterOverride`] so typos surface immediately.
pub fn parse_with_overrides(
    source: &str,
    overrides: &BTreeMap<String, String>,
) -> Result<InvariantFile> {
    // First-pass: tolerant parse to extract `metadata.parameters` (we
    // need them before substitution so we can check the override map).
    let raw: serde_yaml::Value = serde_yaml::from_str(source)?;
    let parameters = extract_parameters(&raw);

    // Reject overrides that target undeclared parameters.
    for key in overrides.keys() {
        if !parameters.contains_key(key) {
            return Err(DslError::UnknownParameterOverride(key.clone()));
        }
    }

    // Build the substitution map: defaults first, overrides on top.
    let mut subst: BTreeMap<String, String> = parameters
        .iter()
        .map(|(name, param)| (name.clone(), stringify_default(&param.default)))
        .collect();
    for (key, value) in overrides {
        subst.insert(key.clone(), value.clone());
    }

    // Phase I — when the file declares `for_each_tool` blocks, we
    // auto-inject `tool_name` as a no-op substitution: any
    // `{{tool_name}}` in the source is replaced by itself, so the
    // literal `{{tool_name}}` survives parse and is later rewritten by
    // [`expand_for_each_tool`] for each matching tool. Users that
    // declare `tool_name` themselves (e.g. for testing) keep their own
    // value.
    if has_for_each_tool(&raw) {
        subst
            .entry("tool_name".to_string())
            .or_insert_with(|| "{{tool_name}}".to_string());
    }

    // Apply mustache substitution on the raw text. Any `{{var}}` that
    // is not in `subst` is collected and reported as a single error.
    let substituted = render_template(source, &subst)?;

    // Final-pass: strict parse + structural validation.
    let file: InvariantFile = serde_yaml::from_str(&substituted)?;
    if file.version == 0 || file.version > MAX_VERSION {
        return Err(DslError::UnsupportedVersion(file.version));
    }
    for invariant in &file.invariants {
        if invariant.generate.is_some() == invariant.fixed.is_some() {
            return Err(DslError::InvalidInputMode(invariant.name.clone()));
        }
    }
    Ok(file)
}

/// Phase I — synthesises a concrete [`Invariant`] from a
/// [`ForEachToolBlock`] template using a placeholder tool name. Used
/// by `wallfacer pack test` to evaluate `apply.test_fixtures` offline,
/// without consulting a live MCP server. The `where` filter is
/// bypassed; the placeholder fills in `{{tool_name}}` everywhere.
pub fn synthesize_for_test(block: &ForEachToolBlock, placeholder: &str) -> Result<Invariant> {
    let yaml = serde_yaml::to_string(&block.apply)?;
    let substituted = yaml
        .replace("{{tool_name}}", placeholder)
        .replace("{{ tool_name }}", placeholder);
    let apply: ApplyTemplate = serde_yaml::from_str(&substituted)?;
    let name = block
        .name
        .replace("{{tool_name}}", placeholder)
        .replace("{{ tool_name }}", placeholder);
    Ok(Invariant {
        name,
        tool: placeholder.to_string(),
        input: apply.input,
        generate: apply.generate,
        fixed: apply.fixed,
        cases: apply.cases,
        assertions: apply.assertions,
        test_fixtures: apply.test_fixtures,
    })
}

/// Phase I — expands every [`ForEachToolBlock`] against the supplied
/// tool list, returning one concrete [`Invariant`] per matching tool.
///
/// Each generated invariant has its `tool` field set to the matched
/// tool's name; `{{tool_name}}` in the block's `name` template (or any
/// string inside the apply body) is rewritten to that name.
///
/// Errors propagate from the regex pre-compile step or from the
/// internal serde round-trip used to substitute `{{tool_name}}` deep
/// in the apply tree.
pub fn expand_for_each_tool(
    blocks: &[ForEachToolBlock],
    tools: &[rmcp::model::Tool],
) -> Result<Vec<Invariant>> {
    let mut out = Vec::new();
    for block in blocks {
        let name_re = block
            .matches
            .name_matches
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|err| DslError::InvalidWhereRegex(err.to_string()))?;
        let description_re = block
            .matches
            .description_matches
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|err| DslError::InvalidWhereRegex(err.to_string()))?;

        for tool in tools {
            if !block
                .matches
                .matches(tool, name_re.as_ref(), description_re.as_ref())
            {
                continue;
            }
            let tool_name = tool.name.as_ref();
            // Substitute {{tool_name}} in the apply tree by serializing
            // the template, doing a string replace, and re-parsing. This
            // keeps the substitution shallow but catches references in
            // any nested string (assertion paths, fixtures, regex
            // patterns, ...).
            let yaml = serde_yaml::to_string(&block.apply)?;
            let substituted = yaml
                .replace("{{tool_name}}", tool_name)
                .replace("{{ tool_name }}", tool_name);
            let apply: ApplyTemplate = serde_yaml::from_str(&substituted)?;
            let name = block
                .name
                .replace("{{tool_name}}", tool_name)
                .replace("{{ tool_name }}", tool_name);
            out.push(Invariant {
                name,
                tool: tool_name.to_string(),
                input: apply.input,
                generate: apply.generate,
                fixed: apply.fixed,
                cases: apply.cases,
                assertions: apply.assertions,
                test_fixtures: apply.test_fixtures,
            });
        }
    }
    Ok(out)
}

impl ToolMatch {
    /// Returns `true` when the tool satisfies every set field on the
    /// filter. Pre-compiled regexes are passed by the caller to avoid
    /// recompiling per tool.
    pub fn matches(
        &self,
        tool: &rmcp::model::Tool,
        name_re: Option<&Regex>,
        description_re: Option<&Regex>,
    ) -> bool {
        let annotations = tool.annotations.as_ref();
        let check_bool = |configured: Option<bool>, actual: Option<bool>| -> bool {
            match configured {
                Some(want) => actual == Some(want),
                None => true,
            }
        };
        if !check_bool(
            self.annotations.read_only_hint,
            annotations.and_then(|a| a.read_only_hint),
        ) {
            return false;
        }
        if !check_bool(
            self.annotations.destructive_hint,
            annotations.and_then(|a| a.destructive_hint),
        ) {
            return false;
        }
        if !check_bool(
            self.annotations.idempotent_hint,
            annotations.and_then(|a| a.idempotent_hint),
        ) {
            return false;
        }
        if !check_bool(
            self.annotations.open_world_hint,
            annotations.and_then(|a| a.open_world_hint),
        ) {
            return false;
        }
        if let Some(re) = name_re {
            if !re.is_match(tool.name.as_ref()) {
                return false;
            }
        }
        if let Some(re) = description_re {
            let description = tool.description.as_deref().unwrap_or("");
            if !re.is_match(description) {
                return false;
            }
        }
        true
    }
}

/// Returns `true` when the parsed YAML carries a non-empty
/// `for_each_tool` array at the document root (Phase I).
fn has_for_each_tool(value: &serde_yaml::Value) -> bool {
    let key = serde_yaml::Value::String("for_each_tool".to_string());
    value
        .as_mapping()
        .and_then(|m| m.get(&key))
        .and_then(|v| v.as_sequence())
        .is_some_and(|seq| !seq.is_empty())
}

/// Walks a parsed YAML value and pulls `metadata.parameters` out as a
/// strict typed map. Returns an empty map if the path is missing or
/// malformed; the caller's strict pass will flag genuinely broken docs.
fn extract_parameters(value: &serde_yaml::Value) -> BTreeMap<String, Parameter> {
    let metadata_key = serde_yaml::Value::String("metadata".to_string());
    let parameters_key = serde_yaml::Value::String("parameters".to_string());
    let Some(metadata) = value.as_mapping().and_then(|m| m.get(&metadata_key)) else {
        return BTreeMap::new();
    };
    let Some(parameters) = metadata.as_mapping().and_then(|m| m.get(&parameters_key)) else {
        return BTreeMap::new();
    };
    serde_yaml::from_value(parameters.clone()).unwrap_or_default()
}

fn stringify_default(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        // Arrays and objects fall back to canonical JSON; users can use
        // them in templates but should typically pick scalar parameters.
        other => other.to_string(),
    }
}

/// Substitutes every `{{name}}` (with optional surrounding whitespace)
/// in `template` using `vars`. Identifier syntax matches Rust's loose
/// snake-case identifiers: `[A-Za-z_][A-Za-z0-9_]*`.
#[allow(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "static regex pattern is checked at compile-time review and cannot fail at runtime"
)]
fn render_template(template: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    // Compile once per call; the regex is small and patterns this short
    // are fast enough that caching across calls is overkill.
    let re =
        Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").expect("static regex must compile");
    let mut missing: Vec<String> = Vec::new();
    let result = re.replace_all(template, |captures: &regex::Captures<'_>| {
        let name = captures.get(1).map(|m| m.as_str()).unwrap_or("");
        match vars.get(name) {
            Some(value) => value.clone(),
            None => {
                if !missing.iter().any(|existing| existing == name) {
                    missing.push(name.to_string());
                }
                captures
                    .get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default()
            }
        }
    });
    if !missing.is_empty() {
        return Err(DslError::UndefinedParameters(missing));
    }
    Ok(result.into_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn v1_legacy_form_still_parses() {
        let source = r#"
version: 1
invariants:
  - name: demo
    tool: echo
    fixed: { text: hello }
    assert:
      - kind: equals
        lhs: "$.response.text"
        rhs: "$.input.text"
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.version, 1);
        assert_eq!(file.invariants.len(), 1);
        match &file.invariants[0].assertions[0] {
            Assertion::Equals { lhs, rhs } => {
                // Heuristic form: a bare string starting with `$` deserialises
                // into Operand::Direct, and the runner resolves it as a path.
                assert!(matches!(lhs, Operand::Direct(Value::String(s)) if s == "$.response.text"));
                assert!(matches!(rhs, Operand::Direct(Value::String(s)) if s == "$.input.text"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn v2_explicit_operands_parse() {
        let source = r#"
version: 2
invariants:
  - name: demo
    tool: echo
    fixed: { text: hello }
    assert:
      - kind: equals
        lhs: { path: "$.response.text" }
        rhs: { value: hello }
"#;
        let file = parse(source).unwrap();
        match &file.invariants[0].assertions[0] {
            Assertion::Equals { lhs, rhs } => {
                assert!(matches!(lhs, Operand::Path { path } if path == "$.response.text"));
                assert!(
                    matches!(rhs, Operand::Literal { value } if value == &Value::String("hello".into()))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn combinators_round_trip() {
        let source = r#"
version: 2
invariants:
  - name: combinators
    tool: t
    fixed: {}
    assert:
      - kind: all_of
        assert:
          - kind: equals
            lhs: { path: "$.response.a" }
            rhs: { value: 1 }
          - kind: any_of
            assert:
              - kind: at_least
                path: "$.response.b"
                value: { value: 0 }
              - kind: not
                assertion:
                  kind: equals
                  lhs: { path: "$.response.b" }
                  rhs: { value: -1 }
"#;
        let file = parse(source).unwrap();
        let serialized = serde_yaml::to_string(&file).unwrap();
        let reparsed = parse(&serialized).unwrap();
        assert_eq!(reparsed.invariants.len(), 1);
        // Walking down the tree confirms the structure round-tripped.
        let Assertion::AllOf { assertions } = &reparsed.invariants[0].assertions[0] else {
            panic!("expected all_of");
        };
        assert_eq!(assertions.len(), 2);
        assert!(matches!(assertions[1], Assertion::AnyOf { .. }));
    }

    #[test]
    fn for_each_parses() {
        let source = r#"
version: 2
invariants:
  - name: items
    tool: list
    fixed: {}
    assert:
      - kind: for_each
        path: "$.response.items[*]"
        assert:
          - kind: is_type
            path: "$.item.id"
            type: integer
"#;
        let file = parse(source).unwrap();
        let Assertion::ForEach { path, assertions } = &file.invariants[0].assertions[0] else {
            panic!("expected for_each");
        };
        assert_eq!(path, "$.response.items[*]");
        assert_eq!(assertions.len(), 1);
    }

    #[test]
    fn matches_schema_carries_inline_schema() {
        let source = r#"
version: 2
invariants:
  - name: shape
    tool: t
    fixed: {}
    assert:
      - kind: matches_schema
        path: "$.response.user"
        schema:
          type: object
          required: [name]
          properties:
            name: { type: string }
"#;
        let file = parse(source).unwrap();
        let Assertion::MatchesSchema { path, schema } = &file.invariants[0].assertions[0] else {
            panic!("expected matches_schema");
        };
        assert_eq!(path, "$.response.user");
        assert_eq!(schema["type"], Value::String("object".into()));
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required[0], Value::String("name".into()));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let source = r#"
version: 99
invariants: []
"#;
        let err = parse(source).unwrap_err();
        assert!(matches!(err, DslError::UnsupportedVersion(99)));
    }

    #[test]
    fn generate_xor_fixed_is_enforced() {
        let source = r#"
version: 2
invariants:
  - name: bad
    tool: t
    generate: { x: { type: integer, min: 0, max: 1 } }
    fixed: { x: 0 }
    assert: []
"#;
        let err = parse(source).unwrap_err();
        assert!(matches!(err, DslError::InvalidInputMode(_)));
    }

    // ---------- Phase G — v3 metadata + templating ----------

    #[test]
    fn v3_minimal_pack_parses() {
        let source = r#"
version: 3
metadata:
  name: demo
  description: "demo pack"
  authors: ["wallfacer-core"]
  tags: [security]
invariants:
  - name: t
    tool: echo
    fixed: {}
    assert:
      - kind: equals
        lhs: { value: 1 }
        rhs: { value: 1 }
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.version, 3);
        let meta = file.metadata.as_ref().expect("metadata");
        assert_eq!(meta.name.as_deref(), Some("demo"));
        assert_eq!(meta.tags, vec!["security".to_string()]);
    }

    #[test]
    fn templating_substitutes_defaults() {
        let source = r#"
version: 3
metadata:
  name: demo
  parameters:
    whoami_tool:
      description: tool returning the current user
      type: string
      default: whoami
invariants:
  - name: t
    tool: "{{whoami_tool}}"
    fixed: {}
    assert: []
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.invariants[0].tool, "whoami");
    }

    #[test]
    fn templating_overrides_take_precedence() {
        let source = r#"
version: 3
metadata:
  name: demo
  parameters:
    whoami_tool:
      type: string
      default: whoami
invariants:
  - name: t
    tool: "{{whoami_tool}}"
    fixed: {}
    assert: []
"#;
        let mut overrides = BTreeMap::new();
        overrides.insert("whoami_tool".to_string(), "getCurrentUser".to_string());
        let file = parse_with_overrides(source, &overrides).unwrap();
        assert_eq!(file.invariants[0].tool, "getCurrentUser");
    }

    #[test]
    fn templating_undeclared_reference_errors() {
        let source = r#"
version: 3
metadata:
  name: demo
invariants:
  - name: t
    tool: "{{whoami_tool}}"
    fixed: {}
    assert: []
"#;
        let err = parse(source).unwrap_err();
        match err {
            DslError::UndefinedParameters(names) => {
                assert_eq!(names, vec!["whoami_tool".to_string()]);
            }
            other => panic!("expected UndefinedParameters, got {other:?}"),
        }
    }

    #[test]
    fn templating_unknown_override_errors() {
        let source = r#"
version: 3
metadata:
  name: demo
invariants:
  - name: t
    tool: echo
    fixed: {}
    assert: []
"#;
        let mut overrides = BTreeMap::new();
        overrides.insert("typoed".to_string(), "x".to_string());
        let err = parse_with_overrides(source, &overrides).unwrap_err();
        assert!(matches!(err, DslError::UnknownParameterOverride(name) if name == "typoed"));
    }

    #[test]
    fn templating_handles_repeated_references() {
        let source = r#"
version: 3
metadata:
  name: demo
  parameters:
    user_tool:
      type: string
      default: whoami
invariants:
  - name: same
    tool: "{{user_tool}}"
    fixed: {}
    assert:
      - kind: equals
        lhs: { path: "$.input" }
        rhs: { value: "{{ user_tool }}" }
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.invariants[0].tool, "whoami");
    }

    #[test]
    fn v2_packs_remain_valid_under_v3_parser() {
        // No `metadata`, no `{{...}}`. Phase G must not break this.
        let source = r#"
version: 2
invariants:
  - name: legacy
    tool: echo
    fixed: { x: 1 }
    assert:
      - kind: equals
        lhs: { path: "$.input.x" }
        rhs: { value: 1 }
"#;
        let file = parse(source).unwrap();
        assert_eq!(file.version, 2);
        assert!(file.metadata.is_none());
    }

    #[test]
    fn v3_round_trip_serde_preserves_metadata_and_invariants() {
        let source = r#"
version: 3
metadata:
  name: roundtrip
  description: probe for serde drift
  authors: [w]
  tags: [t]
  parameters:
    a: { type: string, default: foo }
  extends: [parent]
invariants:
  - name: i1
    tool: "{{a}}"
    fixed: {}
    assert: []
"#;
        let parsed = parse(source).unwrap();
        let yaml = serde_yaml::to_string(&parsed).unwrap();
        let reparsed = parse(&yaml).unwrap();
        assert_eq!(parsed.invariants.len(), reparsed.invariants.len());
        let m1 = parsed.metadata.unwrap();
        let m2 = reparsed.metadata.unwrap();
        assert_eq!(m1.name, m2.name);
        assert_eq!(m1.tags, m2.tags);
        assert_eq!(m1.extends, m2.extends);
        assert_eq!(m1.parameters.len(), m2.parameters.len());
    }

    // ---------- Phase I — for_each_tool ----------

    fn make_tool(name: &str, read_only: Option<bool>) -> rmcp::model::Tool {
        let mut tool = rmcp::model::Tool::new(
            name.to_string(),
            "test tool".to_string(),
            std::sync::Arc::new(serde_json::Map::new()),
        );
        if let Some(read_only) = read_only {
            let mut annotations = rmcp::model::ToolAnnotations::default();
            annotations.read_only_hint = Some(read_only);
            tool = tool.annotate(annotations);
        }
        tool
    }

    #[test]
    fn for_each_tool_apply_parses_input_schema_valid() {
        let source = r#"
version: 3
metadata:
  name: schema-valid
for_each_tool:
  - name: "schema-valid.{{tool_name}}"
    where:
      annotations:
        readOnlyHint: true
    apply:
      input: schema_valid
      assert:
        - kind: equals
          lhs: { path: "$.response.isError" }
          rhs: { value: false }
invariants: []
"#;
        let file = parse(source).expect("parse");
        assert_eq!(file.for_each_tool.len(), 1);
        assert_eq!(
            file.for_each_tool[0].apply.input,
            Some(InputMode::SchemaValid),
            "`input: schema_valid` did not deserialise into the new enum"
        );
        // `fixed` and `generate` stay None when only `input:` is set.
        assert!(file.for_each_tool[0].apply.fixed.is_none());
        assert!(file.for_each_tool[0].apply.generate.is_none());
    }

    #[test]
    fn for_each_tool_parses_with_auto_injected_tool_name() {
        let source = r#"
version: 3
metadata:
  name: tool-annotations
for_each_tool:
  - name: "tool-annotations.read_only_does_not_mutate.{{tool_name}}"
    where:
      annotations:
        readOnlyHint: true
    apply:
      fixed: {}
      assert:
        - kind: matches_schema
          path: "$.response.structuredContent"
          schema: { type: object }
invariants: []
"#;
        let file = parse(source).expect("parse");
        assert_eq!(file.for_each_tool.len(), 1);
        let block = &file.for_each_tool[0];
        // The literal `{{tool_name}}` survives parsing because we
        // auto-inject it as a no-op substitution.
        assert!(block.name.contains("{{tool_name}}"));
        assert_eq!(
            block.matches.annotations.read_only_hint,
            Some(true),
            "where clause didn't deserialise"
        );
    }

    #[test]
    fn for_each_tool_expands_per_matching_tool() {
        let source = r#"
version: 3
metadata:
  name: tool-annotations
for_each_tool:
  - name: "rule.{{tool_name}}"
    where:
      annotations:
        readOnlyHint: true
    apply:
      fixed: {}
      assert:
        - kind: equals
          lhs: { value: 1 }
          rhs: { value: 1 }
invariants: []
"#;
        let file = parse(source).unwrap();
        let tools = vec![
            make_tool("read_user", Some(true)),
            make_tool("delete_user", Some(false)),
            make_tool("get_status", Some(true)),
            make_tool("no_annotations", None),
        ];
        let expanded = expand_for_each_tool(&file.for_each_tool, &tools).unwrap();
        let names: Vec<String> = expanded.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            names,
            vec!["rule.read_user".to_string(), "rule.get_status".to_string()]
        );
        assert_eq!(expanded[0].tool, "read_user");
    }

    #[test]
    fn for_each_tool_filter_by_name_regex() {
        let source = r#"
version: 3
for_each_tool:
  - name: "rule.{{tool_name}}"
    where:
      name_matches: "^read_"
    apply:
      fixed: {}
      assert: []
invariants: []
"#;
        let file = parse(source).unwrap();
        let tools = vec![
            make_tool("read_user", None),
            make_tool("write_user", None),
            make_tool("read_post", None),
        ];
        let expanded = expand_for_each_tool(&file.for_each_tool, &tools).unwrap();
        let names: Vec<String> = expanded.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            names,
            vec!["rule.read_user".to_string(), "rule.read_post".to_string()]
        );
    }

    #[test]
    fn for_each_tool_substitutes_in_apply_body() {
        let source = r#"
version: 3
for_each_tool:
  - name: "{{tool_name}}.contract"
    where: {}
    apply:
      fixed:
        echo_back: "{{tool_name}}"
      assert:
        - kind: equals
          lhs: { path: "$.input.echo_back" }
          rhs: { value: "{{tool_name}}" }
invariants: []
"#;
        let file = parse(source).unwrap();
        let tools = vec![make_tool("only_one", None)];
        let expanded = expand_for_each_tool(&file.for_each_tool, &tools).unwrap();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name, "only_one.contract");
        let fixed = expanded[0].fixed.as_ref().unwrap();
        assert_eq!(fixed["echo_back"], serde_json::json!("only_one"));
    }
}
