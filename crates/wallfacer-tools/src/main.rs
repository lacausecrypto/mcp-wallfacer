//! Build-time tools for the mcp-wallfacer workspace.
//!
//! Currently provides one subcommand: `gen-pack-docs`, which renders a
//! Markdown reference for every embedded rule pack into `docs/packs/`.
//! Run via:
//!
//! ```bash
//! cargo run -p wallfacer-tools -- gen-pack-docs
//! ```
//!
//! The generated tree is meant to be checked in: changes to packs are
//! reviewed alongside their docs in the same PR.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use wallfacer_core::{
    property::dsl::{parse, Assertion, ForEachToolBlock, InvariantFile, Operand},
    run::EMBEDDED_PACKS,
};

#[derive(Debug, Parser)]
#[command(name = "wallfacer-tools", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Render a Markdown reference for every embedded rule pack.
    GenPackDocs(GenPackDocsArgs),
}

#[derive(Debug, clap::Args)]
struct GenPackDocsArgs {
    /// Directory to write the rendered Markdown into. Defaults to
    /// `docs/packs/` at the workspace root.
    #[arg(long, default_value = "docs/packs")]
    out_dir: PathBuf,
    /// Workspace root. The tool resolves `--out-dir` relative to this
    /// path so callers can run from any cwd.
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenPackDocs(args) => gen_pack_docs(args),
    }
}

fn gen_pack_docs(args: GenPackDocsArgs) -> Result<()> {
    let out_dir = args.workspace.join(&args.out_dir);
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let mut catalog: Vec<(String, String)> = Vec::new();
    for (name, source) in EMBEDDED_PACKS {
        let file = parse(source).with_context(|| format!("parse embedded pack `{name}`"))?;
        let body = render_pack(name, source, &file);
        let path = out_dir.join(format!("{name}.md"));
        fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        let description = file
            .metadata
            .as_ref()
            .and_then(|m| m.description.clone())
            .unwrap_or_default();
        catalog.push(((*name).to_string(), description));
        println!("wrote {}", path.display());
    }

    let index_path = out_dir.join("index.md");
    fs::write(&index_path, render_index(&catalog))
        .with_context(|| format!("write {}", index_path.display()))?;
    println!("wrote {}", index_path.display());

    Ok(())
}

fn render_index(catalog: &[(String, String)]) -> String {
    let mut out = String::new();
    out.push_str("# Wallfacer rule pack catalog\n\n");
    out.push_str(
        "Auto-generated from the embedded YAML packs by \
         `cargo run -p wallfacer-tools -- gen-pack-docs`. Edit a pack's \
         YAML and re-run to refresh.\n\n",
    );
    out.push_str("| Pack | Description |\n");
    out.push_str("|---|---|\n");
    let mut sorted: Vec<&(String, String)> = catalog.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, description) in sorted {
        out.push_str(&format!(
            "| [`{name}`](./{name}.md) | {} |\n",
            escape_md_table_cell(description),
        ));
    }
    out.push('\n');
    out
}

fn render_pack(name: &str, source: &str, file: &InvariantFile) -> String {
    let mut out = String::new();
    let metadata = file.metadata.as_ref();

    out.push_str(&format!("# Pack — `{name}`\n\n"));
    if let Some(desc) = metadata.and_then(|m| m.description.clone()) {
        out.push_str(&format!("> {desc}\n\n"));
    }

    let tags = metadata.map(|m| m.tags.clone()).unwrap_or_default();
    let authors = metadata.map(|m| m.authors.clone()).unwrap_or_default();
    let extends = metadata.map(|m| m.extends.clone()).unwrap_or_default();
    if !tags.is_empty() {
        out.push_str(&format!(
            "**Tags:** {}\n",
            tags.iter()
                .map(|t| format!("`{t}`"))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if !authors.is_empty() {
        out.push_str(&format!("**Authors:** {}\n", authors.join(", ")));
    }
    if !extends.is_empty() {
        let pieces: Vec<String> = extends
            .iter()
            .map(|name| format!("[`{name}`](./{name}.md)"))
            .collect();
        out.push_str(&format!("**Extends:** {}\n", pieces.join(", ")));
    }
    out.push('\n');

    // Parameters section.
    let parameters = metadata.map(|m| &m.parameters);
    if let Some(parameters) = parameters {
        if !parameters.is_empty() {
            out.push_str("## Parameters\n\n");
            out.push_str("| Name | Type | Default | Description |\n");
            out.push_str("|---|---|---|---|\n");
            for (key, param) in parameters {
                let kind = format!("{:?}", param.kind).to_lowercase();
                let default = match &param.default {
                    serde_json::Value::String(s) => {
                        format!("`{}`", escape_md_table_cell(s.clone()))
                    }
                    other => format!(
                        "`{}`",
                        escape_md_table_cell(serde_json::to_string(other).unwrap_or_default()),
                    ),
                };
                out.push_str(&format!(
                    "| `{key}` | {kind} | {default} | {} |\n",
                    escape_md_table_cell(param.description.clone().unwrap_or_default()),
                ));
            }
            out.push('\n');
        }
    }

    if !file.invariants.is_empty() {
        out.push_str("## Invariants\n\n");
        for invariant in &file.invariants {
            out.push_str(&format!("### `{}`\n\n", invariant.name));
            out.push_str(&format!("- **Tool:** `{}`\n", invariant.tool));
            if let Some(generate) = &invariant.generate {
                out.push_str(&format!(
                    "- **Inputs:** generated ({} field(s))\n",
                    generate.len()
                ));
            } else if let Some(fixed) = &invariant.fixed {
                out.push_str(&format!("- **Inputs:** fixed ({} field(s))\n", fixed.len()));
            }
            out.push_str(&format!(
                "- **Assertion summary:** {}\n",
                summarise_assertions(&invariant.assertions),
            ));
            if !invariant.test_fixtures.is_empty() {
                out.push_str(&format!(
                    "- **Test fixtures:** {} (",
                    invariant.test_fixtures.len()
                ));
                let shapes: Vec<String> = invariant
                    .test_fixtures
                    .iter()
                    .map(|f| format!("`{:?}`", f.expect).to_lowercase())
                    .collect();
                out.push_str(&shapes.join(", "));
                out.push_str(")\n");
            }
            out.push('\n');
        }
    }

    if !file.for_each_tool.is_empty() {
        out.push_str("## `for_each_tool` templates\n\n");
        for block in &file.for_each_tool {
            render_for_each_block(block, &mut out);
        }
    }

    out.push_str("## Source\n\n");
    out.push_str("Raw YAML, embedded into the binary at compile time:\n\n");
    out.push_str("```yaml\n");
    out.push_str(source);
    if !source.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("```\n");
    out
}

fn render_for_each_block(block: &ForEachToolBlock, out: &mut String) {
    out.push_str(&format!("### `{}`\n\n", block.name));
    let mut filters: Vec<String> = Vec::new();
    if let Some(b) = block.matches.annotations.read_only_hint {
        filters.push(format!("annotations.readOnlyHint = `{b}`"));
    }
    if let Some(b) = block.matches.annotations.destructive_hint {
        filters.push(format!("annotations.destructiveHint = `{b}`"));
    }
    if let Some(b) = block.matches.annotations.idempotent_hint {
        filters.push(format!("annotations.idempotentHint = `{b}`"));
    }
    if let Some(b) = block.matches.annotations.open_world_hint {
        filters.push(format!("annotations.openWorldHint = `{b}`"));
    }
    if let Some(re) = &block.matches.name_matches {
        filters.push(format!("name matches `{re}`"));
    }
    if let Some(re) = &block.matches.description_matches {
        filters.push(format!("description matches `{re}`"));
    }
    if filters.is_empty() {
        out.push_str("- **Where:** every tool\n");
    } else {
        out.push_str(&format!("- **Where:** {}\n", filters.join(" AND ")));
    }
    out.push_str(&format!(
        "- **Apply assertions:** {}\n",
        summarise_assertions(&block.apply.assertions),
    ));
    if !block.apply.test_fixtures.is_empty() {
        out.push_str(&format!(
            "- **Test fixtures:** {} (",
            block.apply.test_fixtures.len()
        ));
        let shapes: Vec<String> = block
            .apply
            .test_fixtures
            .iter()
            .map(|f| format!("`{:?}`", f.expect).to_lowercase())
            .collect();
        out.push_str(&shapes.join(", "));
        out.push_str(")\n");
    }
    out.push('\n');
}

fn summarise_assertions(assertions: &[Assertion]) -> String {
    if assertions.is_empty() {
        return "(none)".to_string();
    }
    let kinds: Vec<String> = assertions.iter().map(assertion_kind_label).collect();
    kinds.join(" + ")
}

fn assertion_kind_label(assertion: &Assertion) -> String {
    match assertion {
        Assertion::Equals { lhs, rhs } => {
            format!("equals({} == {})", operand_label(lhs), operand_label(rhs))
        }
        Assertion::NotEquals { lhs, rhs } => {
            format!(
                "not_equals({} != {})",
                operand_label(lhs),
                operand_label(rhs)
            )
        }
        Assertion::AtMost { path, .. } => format!("at_most(`{path}`)"),
        Assertion::AtLeast { path, .. } => format!("at_least(`{path}`)"),
        Assertion::LengthEq { path, .. } => format!("length_eq(`{path}`)"),
        Assertion::LengthAtMost { path, .. } => format!("length_at_most(`{path}`)"),
        Assertion::LengthAtLeast { path, .. } => format!("length_at_least(`{path}`)"),
        Assertion::IsType { path, expected } => {
            format!(
                "is_type(`{path}`, {})",
                format!("{expected:?}").to_lowercase()
            )
        }
        Assertion::MatchesRegex { path, .. } => format!("matches_regex(`{path}`)"),
        Assertion::AllOf { assertions } => {
            format!("all_of({} child)", assertions.len())
        }
        Assertion::AnyOf { assertions } => {
            format!("any_of({} child)", assertions.len())
        }
        Assertion::Not { assertion } => format!("not({})", assertion_kind_label(assertion)),
        Assertion::ForEach { path, assertions } => {
            format!("for_each(`{path}`, {} child)", assertions.len())
        }
        Assertion::MatchesSchema { path, .. } => format!("matches_schema(`{path}`)"),
    }
}

fn operand_label(operand: &Operand) -> String {
    match operand {
        Operand::Path { path } => format!("path `{path}`"),
        Operand::Literal { value } => format!(
            "literal `{}`",
            serde_json::to_string(value).unwrap_or_default()
        ),
        Operand::Direct(value) => format!("`{}`", serde_json::to_string(value).unwrap_or_default()),
    }
}

fn escape_md_table_cell<S: AsRef<str>>(text: S) -> String {
    text.as_ref().replace('|', "\\|").replace('\n', " ")
}

#[allow(dead_code)]
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
