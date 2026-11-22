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
mod file_checkpoint;
mod file_client;
mod file_protocol;
mod file_resume;
#[cfg(unix)]
#[path = "file_storage_unix.rs"]
mod file_storage;
#[cfg(windows)]
#[path = "file_storage_windows.rs"]
mod file_storage;
mod file_worker;
mod files;
mod hello;
mod identity;
mod listing;
mod logging;
mod modes;
#[cfg(unix)]
mod process;
#[cfg(windows)]
#[path = "process_windows.rs"]
mod process;
#[cfg(unix)]
mod pty;
#[cfg(windows)]
#[path = "pty_windows.rs"]
mod pty;
mod quic;
mod requests;
mod server;
mod session;
mod terminal;
mod tls;
mod trust;
#[cfg(windows)]
mod windows_security;
mod wire;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__stpt-native-exec")) {
        return process::native_exec();
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__stpt-file-worker")) {
        return crate::file_worker::main();
    }
    match cli::run(cli::Cli::parse_args()) {
        Ok(code) => code,
        Err(e) => {
            // Standard error may be gone (closed terminal window); eprintln would panic.
            let _ = writeln!(std::io::stderr(), "stpt: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
