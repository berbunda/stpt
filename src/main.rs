mod cli;
mod destination;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    cli::run(cli::Cli::parse())
}
