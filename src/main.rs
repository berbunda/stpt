mod auth;
mod authorized;
mod cbor;
mod cli;
mod client;
mod config;
mod console;
mod control;
mod destination;
mod error;
mod hello;
mod identity;
mod logging;
#[cfg(unix)]
mod process;
#[cfg(unix)]
mod pty;
mod quic;
mod server;
#[cfg(unix)]
mod session;
mod terminal;
mod tls;
mod trust;
mod wire;

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
