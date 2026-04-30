mod commands;

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
