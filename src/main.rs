#[cfg(unix)]
mod attachment;
mod auth;
mod authorized;
mod buffer;
mod cbor;
mod cli;
mod client;
mod commands;
mod config;
mod console;
mod control;
mod destination;
mod error;
mod hello;
mod identity;
mod listing;
mod logging;
#[cfg(unix)]
mod process;
#[cfg(unix)]
mod pty;
mod quic;
#[cfg(unix)]
mod requests;
mod server;
#[cfg(unix)]
mod session;
mod terminal;
mod tls;
mod trust;
mod wire;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run(cli::Cli::parse_args()) {
        Ok(code) => code,
        Err(e) => {
            // Standard error may be gone (closed terminal window); eprintln would panic.
            let _ = writeln!(std::io::stderr(), "stpt: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
