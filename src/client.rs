//! Client role: every subcommand except `server`.

use std::process::ExitCode;

use crate::cli::{ClientCommand, Common};
use crate::config::{self, ClientConfig};
use crate::error::Error;
use crate::logging::{self, Role};

pub fn run(command: ClientCommand, common: &Common) -> Result<ExitCode, Error> {
    let (_config, path) =
        config::load::<ClientConfig>(common.config.as_deref(), config::client_path())?;
    logging::init(
        Role::Client,
        logging::level(Role::Client, common.verbose, common.quiet, None),
    );
    config::log_source(path.as_deref());

    let name = match command {
        ClientCommand::Connect { .. } => "connect",
        ClientCommand::Exec { .. } => "exec",
        ClientCommand::Sessions { .. } => "sessions",
        ClientCommand::Detach { .. } => "detach",
        ClientCommand::Terminate { .. } => "terminate",
    };
    Err(Error::NotImplemented(name))
}
