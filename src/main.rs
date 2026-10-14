mod cli;
mod client;
mod destination;
mod server;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    cli::run(cli::Cli::parse())
}
