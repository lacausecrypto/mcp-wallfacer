use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Args};

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("transport").args(["http", "stdio"]).multiple(false)))]
pub struct InitArgs {
    /// Generate the `.github/workflows/wallfacer.yml` workflow alongside
    /// `wallfacer.toml`.
    #[arg(long)]
    pub ci: bool,
    /// Force the generated config to use the HTTP Streamable transport.
    /// Mutually exclusive with `--stdio`.
    #[arg(long)]
    pub http: bool,
    /// Force the generated config to use the stdio transport. Mutually
    /// exclusive with `--http`. When neither flag is set, `init` detects
    /// the project type (npm / Python / Cargo) and falls back to stdio.
    #[arg(long)]
    pub stdio: bool,
    /// Skip writing `invariants.yaml`. By default `init` drops a small
    /// example invariants file next to `wallfacer.toml`.
    #[arg(long)]
    pub skip_invariants: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let config_path = cwd.join("wallfacer.toml");

    if config_path.exists() {
        bail!("wallfacer.toml already exists");
    }

    let transport = pick_transport(&args);
    fs::write(&config_path, template_for(&cwd, transport))
        .context("failed to write wallfacer.toml")?;
    println!("created {}", config_path.display());

    if !args.skip_invariants {
        let invariants_path = cwd.join("invariants.yaml");
        if invariants_path.exists() {
            eprintln!(
                "skipping invariants.yaml (already exists at {})",
                invariants_path.display()
            );
        } else {
            fs::write(&invariants_path, INVARIANTS_EXAMPLE)
                .context("failed to write invariants.yaml")?;
            println!("created {}", invariants_path.display());
        }
    }

    if args.ci {
        let workflow_dir = cwd.join(".github/workflows");
        fs::create_dir_all(&workflow_dir).context("failed to create .github/workflows")?;
        let workflow_path = workflow_dir.join("wallfacer.yml");
        fs::write(&workflow_path, WALLFACER_WORKFLOW)
            .context("failed to write .github/workflows/wallfacer.yml")?;
        println!("created {}", workflow_path.display());
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Transport {
    Stdio,
    Http,
}

fn pick_transport(args: &InitArgs) -> Transport {
    if args.http {
        Transport::Http
    } else {
        // Default and `--stdio` both end up here.
        Transport::Stdio
    }
}

fn template_for(cwd: &Path, transport: Transport) -> String {
    match transport {
        Transport::Stdio => stdio_template(cwd),
        Transport::Http => HTTP_TEMPLATE.to_string(),
    }
}

fn stdio_template(cwd: &Path) -> String {
    let (command, args, note) = detect_target(cwd);
    format!(
        r#"# mcp-wallfacer configuration

[target]
kind = "stdio"
command = "{command}"
args = {args}
timeout_ms = 5000

# Alternative HTTP target:
# [target]
# kind = "http"
# url = "http://localhost:8000/mcp"
# headers = {{ Authorization = "Bearer xxx" }}

[output]
corpus_dir = ".wallfacer/corpus"
# Phase E3: how long Corpus::write_finding waits for the shared lock.
# lock_timeout_ms = 30000

# Override default finding severities:
# [severity]
# protocol_error = "medium"

# Phase C: regex allowlist for tools wallfacer would otherwise classify
# destructive (matched against tool name).
# [allow_destructive]
# tools = ["^logs_.*$"]

# Phase C: replace the default destructive keyword set with custom regexes.
# [destructive]
# patterns = ["^remove_.*$", "^drop_.*$"]

# {note}
"#
    )
}

const HTTP_TEMPLATE: &str = r#"# mcp-wallfacer configuration (HTTP Streamable transport)

[target]
kind = "http"
url = "http://localhost:8000/mcp"
timeout_ms = 5000

[target.headers]
# Authentication is loaded from the env so secrets don't sit in the
# config: leave the file checked into the repo and export the actual
# bearer locally.
Authorization = "Bearer ${WALLFACER_BEARER}"

[output]
corpus_dir = ".wallfacer/corpus"
# lock_timeout_ms = 30000

# [allow_destructive]
# tools = ["^logs_.*$"]

# [destructive]
# patterns = ["^remove_.*$"]
"#;

fn detect_target(cwd: &Path) -> (&'static str, String, &'static str) {
    if cwd.join("package.json").is_file() {
        return (
            "npx",
            "[\"-y\", \"<package>\"]".to_string(),
            "Detected package.json; replace <package> with your MCP server package.",
        );
    }

    if cwd.join("pyproject.toml").is_file() || has_root_python_file(cwd) {
        return (
            "python3",
            "[\"server.py\"]".to_string(),
            "Detected Python project; adjust args to point at your MCP server.",
        );
    }

    if cwd.join("Cargo.toml").is_file() {
        return (
            "cargo",
            "[\"run\", \"--quiet\"]".to_string(),
            "Detected Cargo project; adjust args if your MCP server is a specific binary.",
        );
    }

    (
        "<command>",
        "[\"<arg>\"]".to_string(),
        "No project type detected; fill in the stdio command manually.",
    )
}

fn has_root_python_file(cwd: &Path) -> bool {
    fs::read_dir(cwd)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .any(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "py")
        })
}

const INVARIANTS_EXAMPLE: &str = r#"# wallfacer property invariants — v2 syntax.
# Run with: `wallfacer property invariants.yaml`
#
# A handful of starter invariants. Extend with your tools' contracts; the
# v2 DSL supports all_of / any_of / not / for_each / matches_schema, plus
# explicit { path: "..." } / { value: ... } operands.
version: 2
invariants:
  - name: "echo returns input verbatim"
    tool: echo
    fixed:
      text: "hello"
    assert:
      - kind: equals
        lhs: { path: "$.response.content[0].text" }
        rhs: { value: "hello" }

  - name: "no tool ever leaks the wallfacer placeholder"
    tool: echo
    fixed:
      text: "hello"
    assert:
      - kind: not
        assertion:
          kind: matches_regex
          path: "$.response.content[0].text"
          pattern: "<wallfacer-secret>"
"#;

const WALLFACER_WORKFLOW: &str = r#"name: mcp-wallfacer
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  wallfacer:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: taiki-e/install-action@v2
        with:
          tool: mcp-wallfacer@latest
      # If your MCP server is Python-based, uncomment:
      # - uses: actions/setup-python@v5
      #   with: { python-version: "3.11" }
      # - run: pip install -r requirements.txt
      - run: wallfacer ci --format sarif --severity-threshold medium > wallfacer.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: wallfacer.sarif
"#;
