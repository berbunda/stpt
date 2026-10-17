mod cli;
mod client;
mod config;
mod destination;
mod error;
mod identity;
mod logging;
mod quic;
mod server;
mod tls;
mod trust;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run(cli::Cli::parse_args()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stpt: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
