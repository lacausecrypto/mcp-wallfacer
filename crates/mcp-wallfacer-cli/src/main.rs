mod commands;
mod reporters;

use std::{io::IsTerminal, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "mcp-wallfacer", bin_name = "wallfacer", version, about)]
struct Cli {
    #[arg(long, global = true, env = "WALLFACER_CONFIG")]
    config: Option<PathBuf>,
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Init(commands::init::InitArgs),
    Doctor(commands::doctor::DoctorArgs),
    Fuzz(commands::fuzz::FuzzArgs),
    Differential(commands::differential::DifferentialArgs),
    Property(commands::property::PropertyArgs),
    Torture(commands::torture::TortureArgs),
    Corpus(commands::corpus::CorpusArgs),
    Ci(commands::ci::CiArgs),
    /// Re-run a stored finding against the configured target. Looks up
    /// `WALLFACER_REPLAY_<KEY>` env vars to substitute back any redacted
    /// payload field locally; substitutions are never logged.
    Replay(commands::replay::ReplayArgs),
    /// Compare two corpus directories and report regressions / fixes.
    Diff(commands::diff::DiffArgs),
    /// Manage rule packs: list, show, init, test (offline fixture
    /// runner), params.
    Pack(commands::pack::PackArgs),
    /// Phase P — connect to the configured target, list its tools, and
    /// suggest which embedded rule packs apply (with parameter
    /// overrides pre-filled from the observable tool catalog).
    Suggest(commands::suggest::SuggestArgs),
    /// Phase Q — print a static `(tool, pack)` coverage matrix from
    /// the configured target's tool list and the pack set; supports
    /// `--strict` to gate CI on tools no pack would exercise.
    Coverage(commands::coverage::CoverageArgs),
    /// Phase U — render a self-contained HTML / JSON dashboard from
    /// the persisted findings under the corpus directory. Open the
    /// HTML output in any browser, no internet / server required.
    Report(commands::report::ReportArgs),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Some(Command::Init(args)) => commands::init::run(args).await,
        Some(Command::Doctor(args)) => commands::doctor::run(args, cli.config.as_deref()).await,
        Some(Command::Fuzz(args)) => commands::fuzz::run(args, cli.config.as_deref()).await,
        Some(Command::Differential(args)) => {
            commands::differential::run(args, cli.config.as_deref()).await
        }
        Some(Command::Property(args)) => commands::property::run(args, cli.config.as_deref()).await,
        Some(Command::Torture(args)) => commands::torture::run(args, cli.config.as_deref()).await,
        Some(Command::Corpus(args)) => commands::corpus::run(args, cli.config.as_deref()).await,
        Some(Command::Ci(args)) => commands::ci::run(args, cli.config.as_deref()).await,
        Some(Command::Replay(args)) => commands::replay::run(args, cli.config.as_deref()).await,
        Some(Command::Diff(args)) => commands::diff::run(args).await,
        Some(Command::Pack(args)) => commands::pack::run(args, cli.config.as_deref()).await,
        Some(Command::Suggest(args)) => commands::suggest::run(args, cli.config.as_deref()).await,
        Some(Command::Coverage(args)) => commands::coverage::run(args, cli.config.as_deref()).await,
        Some(Command::Report(args)) => commands::report::run(args, cli.config.as_deref()).await,
        None => {
            println!("mcp-wallfacer {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn init_tracing(verbosity: u8) {
    let default_filter = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_ansi(std::io::stderr().is_terminal())
        .try_init();
}
