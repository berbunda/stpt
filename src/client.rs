//! Client role: every subcommand except `server`.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::{ClientCommand, EXIT_STPT_ERROR};
use crate::config::{self, ClientConfig};

pub fn run(command: ClientCommand, config_path: Option<&Path>) -> ExitCode {
    let _config: ClientConfig = match config::load(config_path, config::client_path()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("stpt: config: {e}");
            return ExitCode::from(EXIT_STPT_ERROR);
        }
    };
    let name = match command {
        ClientCommand::Connect { .. } => "connect",
        ClientCommand::Exec { .. } => "exec",
        ClientCommand::Sessions { .. } => "sessions",
        ClientCommand::Detach { .. } => "detach",
        ClientCommand::Terminate { .. } => "terminate",
    };
    eprintln!("stpt: {name}: not implemented yet");
    ExitCode::from(EXIT_STPT_ERROR)
}
