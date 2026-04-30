use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "mcp-wallfacer", bin_name = "wallfacer", version, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!("mcp-wallfacer {}", env!("CARGO_PKG_VERSION"));
}
