mod attachment;
mod auth;
mod authorized;
mod buffer;
mod cbor;
mod cli;
mod client;
mod commands;
mod config;
mod consent;
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
mod forwarding;
#[cfg(target_os = "linux")]
mod fuse_mount;
mod hello;
mod identity;
mod listing;
mod logging;
mod modes;
mod permissions;
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
mod reverse;
mod server;
mod session;
mod session_local;
mod terminal;
mod tls;
mod trust;
#[cfg(windows)]
mod windows_security;
mod wire;

#[cfg(test)]
#[path = "wire/parser_fuzz.rs"]
mod parser_fuzz;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(unix)]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__stpt-network-worker"))
    {
        return forwarding::native::helper();
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__stpt-mount-tree")) {
        return if reverse::mount_client::helper().is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__stpt-fuse")) {
        return match fuse_mount::helper() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
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
