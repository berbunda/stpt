//! Client role: every subcommand except `server`.

use std::process::ExitCode;

use crate::cli::{ClientCommand, EXIT_STPT_ERROR};

pub fn run(command: ClientCommand) -> ExitCode {
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
