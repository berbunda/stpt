//! Command line interface: one explicit subcommand per operation.
//!
//! The subcommand selects the role of the binary: `server` runs the Server,
//! every other subcommand runs the Client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};

use crate::destination::Destination;
use crate::error::Error;
use crate::{client, server};

/// Secure terminal access over QUIC.
#[derive(Debug, Parser)]
#[command(name = "stpt", version, propagate_version = true)]
pub struct Cli {
    #[command(flatten)]
    pub common: Common,

    #[command(subcommand)]
    pub command: Command,
}

/// Options of both roles, accepted before or after the subcommand.
#[derive(Debug, Args)]
pub struct Common {
    /// Configuration file instead of the default one
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// More log messages: -v info, -vv debug, -vvv trace
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Log errors only
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

impl Cli {
    /// Parses the command line; a usage error exits with 2.
    pub fn parse_args() -> Self {
        Self::parse().validate().unwrap_or_else(|e| e.exit())
    }

    /// Checks that clap cannot express: `conflicts_with` misses global options
    /// given on different levels (`-q server -v`).
    fn validate(self) -> Result<Self, clap::Error> {
        if self.common.quiet && self.common.verbose > 0 {
            return Err(Self::command().error(
                ErrorKind::ArgumentConflict,
                "--quiet cannot be used with --verbose",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the Server
    Server {
        /// Address and UDP port to listen on [default: all addresses, port 843]
        #[arg(long, value_name = "ADDR:PORT")]
        listen: Option<SocketAddr>,
    },

    #[command(flatten)]
    Client(ClientCommand),
}

/// Subcommands of the Client role.
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Open an interactive terminal in a new or an existing Session
    Connect {
        /// Account on the Server and Server address [default port: 843]
        #[arg(value_name = "ACCOUNT@HOST[:PORT]")]
        destination: Destination,

        /// Attach to an existing Session instead of creating one
        #[arg(long, value_name = "SESSION")]
        attach: Option<String>,

        /// Name of the new Session
        #[arg(long, conflicts_with = "attach")]
        name: Option<String>,

        /// Detach all other Attachments of the Session first
        #[arg(long, requires = "attach")]
        takeover: bool,

        /// Receive output only
        #[arg(long, requires = "attach")]
        read_only: bool,
    },

    /// Run a command in a new Session
    Exec {
        /// Account on the Server and Server address [default port: 843]
        #[arg(value_name = "ACCOUNT@HOST[:PORT]")]
        destination: Destination,

        /// Run the command as an argument vector, without the Account's shell
        #[arg(long)]
        no_shell: bool,

        /// Command and its arguments
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// List the Sessions of the Account
    Sessions {
        /// Account on the Server and Server address [default port: 843]
        #[arg(value_name = "ACCOUNT@HOST[:PORT]")]
        destination: Destination,
    },

    /// Detach Attachments of a Session
    Detach {
        /// Account on the Server and Server address [default port: 843]
        #[arg(value_name = "ACCOUNT@HOST[:PORT]")]
        destination: Destination,

        /// Session ID, unique ID prefix or name
        #[arg(value_name = "SESSION")]
        session: String,

        #[command(flatten)]
        target: DetachTarget,
    },

    /// Terminate a Session
    Terminate {
        /// Account on the Server and Server address [default port: 843]
        #[arg(value_name = "ACCOUNT@HOST[:PORT]")]
        destination: Destination,

        /// Session ID, unique ID prefix or name
        #[arg(value_name = "SESSION")]
        session: String,

        /// Kill the processes at once, without the grace period
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct DetachTarget {
    /// Detach all Attachments
    #[arg(long)]
    pub all: bool,

    /// Detach the Attachment with this ID
    #[arg(long, value_name = "ATTACHMENT")]
    pub id: Option<u64>,
}

pub fn run(cli: Cli) -> Result<ExitCode, Error> {
    match cli.command {
        Command::Server { listen } => server::run(listen, &cli.common),
        Command::Client(command) => client::run(command, &cli.common),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("stpt").chain(args.iter().copied()))?.validate()
    }

    fn err_kind(args: &[&str]) -> ErrorKind {
        parse(args).unwrap_err().kind()
    }

    #[test]
    fn definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn server_listen() {
        let cli = parse(&["server", "--listen", "[::]:843"]).unwrap();
        assert!(matches!(cli.command, Command::Server { listen: Some(a) } if a.port() == 843));
        assert!(matches!(
            parse(&["server"]).unwrap().command,
            Command::Server { listen: None }
        ));
    }

    #[test]
    fn config_before_or_after_subcommand() {
        for args in [
            &["--config", "a.toml", "server"][..],
            &["server", "--config", "a.toml"],
            &["connect", "alice@host", "--config", "a.toml"],
        ] {
            let cli = parse(args).unwrap();
            assert_eq!(cli.common.config, Some(PathBuf::from("a.toml")), "{args:?}");
        }
        assert_eq!(parse(&["server"]).unwrap().common.config, None);
    }

    #[test]
    fn verbosity() {
        assert_eq!(parse(&["-vv", "server"]).unwrap().common.verbose, 2);
        assert_eq!(
            parse(&["server", "-v", "-v", "-v"]).unwrap().common.verbose,
            3
        );
        assert!(parse(&["server", "-q"]).unwrap().common.quiet);
        assert_eq!(
            err_kind(&["-q", "server", "-v"]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(err_kind(&["server", "-qv"]), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn other_subcommands_select_client() {
        let cases: [&[&str]; 5] = [
            &["connect", "alice@host"],
            &["exec", "alice@host", "true"],
            &["sessions", "alice@host"],
            &["detach", "alice@host", "work", "--all"],
            &["terminate", "alice@host", "work"],
        ];
        for args in cases {
            assert!(
                matches!(parse(args).unwrap().command, Command::Client(_)),
                "{args:?}"
            );
        }
    }

    #[test]
    fn connect_new_and_attach() {
        let cli = parse(&["connect", "alice@host", "--name", "work"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Client(ClientCommand::Connect {
                attach: None,
                name: Some(_),
                ..
            })
        ));

        let cli = parse(&["connect", "alice@host", "--attach", "work", "--takeover"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Client(ClientCommand::Connect {
                attach: Some(_),
                takeover: true,
                ..
            })
        ));
    }

    #[test]
    fn connect_conflicts() {
        assert_eq!(
            err_kind(&["connect", "alice@host", "--attach", "s", "--name", "n"]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            err_kind(&["connect", "alice@host", "--takeover"]),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            err_kind(&["connect", "alice@host", "--read-only"]),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn invalid_destination() {
        assert_eq!(err_kind(&["connect", "host"]), ErrorKind::ValueValidation);
    }

    #[test]
    fn exec_keeps_command_arguments() {
        let cli = parse(&["exec", "alice@host", "ls", "-la", "/tmp"]).unwrap();
        let Command::Client(ClientCommand::Exec {
            command, no_shell, ..
        }) = cli.command
        else {
            panic!()
        };
        assert_eq!(command, ["ls", "-la", "/tmp"]);
        assert!(!no_shell);

        let cli = parse(&["exec", "alice@host", "--no-shell", "--", "ls", "-la"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Client(ClientCommand::Exec { no_shell: true, .. })
        ));

        assert_eq!(
            err_kind(&["exec", "alice@host"]),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn detach_needs_exactly_one_target() {
        assert!(parse(&["detach", "alice@host", "work", "--all"]).is_ok());
        assert!(parse(&["detach", "alice@host", "work", "--id", "3"]).is_ok());
        assert_eq!(
            err_kind(&["detach", "alice@host", "work"]),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            err_kind(&["detach", "alice@host", "work", "--all", "--id", "3"]),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn terminate_force() {
        let cli = parse(&["terminate", "alice@host", "work", "--force"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Client(ClientCommand::Terminate { force: true, .. })
        ));
    }
}
