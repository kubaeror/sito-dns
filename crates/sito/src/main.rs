//! Binary entry point for the `sito` DNS server CLI.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "sito")]
#[command(author, version, about = "High-performance, self-hosted, filtering DNS server", long_about = None)]
struct Cli {}

fn main() {
    let _args = Cli::parse();
}
