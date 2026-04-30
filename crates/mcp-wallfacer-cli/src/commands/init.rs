use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use clap::Args;

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub ci: bool,
}

pub async fn run(args: InitArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let config_path = cwd.join("wallfacer.toml");

    if config_path.exists() {
        bail!("wallfacer.toml already exists");
    }

    fs::write(&config_path, template_for(&cwd)).context("failed to write wallfacer.toml")?;
    println!("created {}", config_path.display());

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

fn template_for(cwd: &Path) -> String {
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

# Override default finding severities:
# [severity]
# protocol_error = "medium"

# Whitelist explicitly accepted destructive tools:
# [allow_destructive]
# tools = ["delete_old_logs"]

# {note}
"#
    )
}

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
