//! Processes of a Session (Unix; PROTOCOL.md §14.6).
//!
//! The Server starts the login shell or the command of a Session as the Account: in a
//! new session (`setsid`), with a PTY slave as controlling terminal and as standard
//! input, output and error, or with three pipes; groups, group and user of the
//! Account; working directory
//! its home (`/` if that fails); an environment built from scratch, so nothing of the
//! Server's own environment reaches the Account.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use nix::unistd::{Gid, Uid, User};
use tokio::process::{Child, Command};

/// PATH of the Account's processes, as Debian's `login.defs` sets it.
const PATH_USER: &str = "/usr/local/bin:/usr/bin:/bin";
const PATH_ROOT: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Shell of an Account without one in the user database.
const DEFAULT_SHELL: &str = "/bin/sh";

/// An operating system Account, as found in the user database.
#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    uid: Uid,
    gid: Gid,
    groups: Vec<Gid>,
    home: PathBuf,
    shell: PathBuf,
}

impl Account {
    /// Looks the Account up (`getpwnam`, `getgrouplist`); blocks.
    pub fn lookup(name: &str) -> io::Result<Option<Account>> {
        let Some(user) = User::from_name(name)? else {
            return Ok(None);
        };
        let c_name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let groups = nix::unistd::getgrouplist(&c_name, user.gid)?;
        let shell = if user.shell.as_os_str().is_empty() {
            PathBuf::from(DEFAULT_SHELL)
        } else {
            user.shell
        };
        Ok(Some(Account {
            name: user.name,
            uid: user.uid,
            gid: user.gid,
            groups,
            home: user.dir,
            shell,
        }))
    }
}

/// What a Session runs (§14.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// The Account's shell as a login shell.
    LoginShell,
    /// A command line, run by the Account's shell with `-c`.
    Shell(String),
    /// An argument vector, not empty: each element reaches the program unchanged.
    Argv(Vec<String>),
}

/// Standard input, output and error of the processes.
pub enum Io {
    /// The slave of a PTY with its terminal type; it becomes the controlling terminal.
    Pty { slave: OwnedFd, term: String },
    /// Three pipes, available on the Child.
    Pipes,
}

nix::ioctl_write_int_bad!(set_controlling_terminal, nix::libc::TIOCSCTTY);

/// Starts `program` as `account` in a new session, which is also its own process
/// group (§14.9). `env` holds further variables: those taken from the Client, already
/// checked against the allowlist, and `STPT_SESSION`. The Server must run as root, or
/// as the Account itself.
pub fn spawn(
    account: &Account,
    program: &Program,
    env: &[(String, String)],
    io: Io,
) -> io::Result<Child> {
    let switch_user = nix::unistd::geteuid().is_root();
    if !switch_user && account.uid != nix::unistd::geteuid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the Server runs neither as root nor as the Account",
        ));
    }

    let mut command = command(account, program);
    command
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("SHELL", &account.shell)
        .env(
            "PATH",
            if account.uid.is_root() {
                PATH_ROOT
            } else {
                PATH_USER
            },
        )
        .envs(env.iter().map(|(name, value)| (name, value)));
    let pty = matches!(io, Io::Pty { .. });
    match io {
        Io::Pty { slave, term } => command
            .env("TERM", term)
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave)),
        Io::Pipes => command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    };

    let uid = account.uid;
    let gid = account.gid;
    let groups = account.groups.clone();
    let home = CString::new(account.home.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "home directory contains NUL"))?;
    // SAFETY: the closure runs in the child between fork and exec. It only makes
    // system calls and does not allocate: everything it needs is prepared here.
    unsafe {
        command.pre_exec(move || {
            nix::unistd::setsid()?;
            if pty {
                // Standard input is the slave already; it becomes the controlling terminal.
                set_controlling_terminal(0, 0)?;
            }
            if switch_user {
                nix::unistd::setgroups(&groups)?;
                nix::unistd::setgid(gid)?;
                nix::unistd::setuid(uid)?;
            }
            if nix::unistd::chdir(home.as_c_str()).is_err() {
                nix::unistd::write(
                    std::io::stderr(),
                    b"stpt: cannot change to the home directory, starting in /\n",
                )?;
                nix::unistd::chdir("/")?;
            }
            Ok(())
        });
    }
    command.spawn()
}

/// The command for `program`: a login shell gets `-` before the name of the shell as
/// its argument 0, as login(1) and sshd start it. An argument vector also goes
/// through the Account's shell, quoted, so a disabled or restricted shell (`nologin`,
/// `git-shell`) keeps its effect.
fn command(account: &Account, program: &Program) -> Command {
    let mut command = Command::new(&account.shell);
    match program {
        Program::LoginShell => command.arg0(login_name(&account.shell)),
        Program::Shell(line) => command.arg("-c").arg(line),
        Program::Argv(argv) => {
            let line: Vec<String> = argv.iter().map(|a| quote(a)).collect();
            command.arg("-c").arg(line.join(" "))
        }
    };
    command
}

/// Quotes an argument for a POSIX shell: in single quotes, `'` as `'\''`.
fn quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

fn login_name(shell: &Path) -> std::ffi::OsString {
    let mut name = std::ffi::OsString::from("-");
    name.push(shell.file_name().unwrap_or(OsStr::new("sh")));
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pty::{Master, Pty, Size};
    use std::os::unix::process::ExitStatusExt;

    const SIZE: Size = Size {
        columns: 80,
        rows: 24,
        width: 0,
        height: 0,
    };

    fn me() -> Account {
        let name = User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name;
        Account::lookup(&name).unwrap().unwrap()
    }

    async fn output(master: &Master) -> String {
        let mut out = Vec::new();
        let mut buf = [0; 1024];
        loop {
            match master.read(&mut buf).await.unwrap() {
                0 => return String::from_utf8(out).unwrap(),
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Runs `program` on a new PTY; output and exit status.
    async fn run(
        account: &Account,
        program: Program,
        env: &[(String, String)],
    ) -> (String, std::process::ExitStatus) {
        let Pty { master, slave } = Pty::open(SIZE).unwrap();
        let term = "xterm-256color".to_owned();
        let mut child = spawn(account, &program, env, Io::Pty { slave, term }).unwrap();
        let out = output(&master).await;
        (out, child.wait().await.unwrap())
    }

    #[test]
    fn unknown_account() {
        assert!(Account::lookup("stpt-no-such-account").unwrap().is_none());
    }

    #[test]
    fn account_of_root() {
        let root = Account::lookup("root").unwrap().unwrap();
        assert!(root.uid.is_root());
        assert_eq!(root.home, Path::new("/root"));
        assert!(root.groups.contains(&root.gid));
    }

    #[test]
    fn login_shell_name() {
        assert_eq!(login_name(Path::new("/bin/bash")), "-bash");
    }

    #[tokio::test]
    async fn command_on_controlling_terminal() {
        let me = me();
        // /dev/tty opens only on a controlling terminal.
        let line = "exec 3</dev/tty && echo ctty; pwd; echo $TERM; exit 3".to_owned();
        let (out, status) = run(&me, Program::Shell(line), &[]).await;
        let home = me.home.to_str().unwrap();
        assert_eq!(out, format!("ctty\r\n{home}\r\nxterm-256color\r\n"));
        assert_eq!(status.code(), Some(3));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote(""), "''");
    }

    #[tokio::test]
    async fn argument_vector_unchanged() {
        let argv = ["printf", "%s|", "a b", "$HOME", "it's", "*", ""].map(String::from);
        let (out, status) = run(&me(), Program::Argv(argv.to_vec()), &[]).await;
        assert_eq!(out, "a b|$HOME|it's|*||");
        assert!(status.success());
    }

    #[tokio::test]
    async fn environment_from_scratch() {
        let env = [("LANG".to_owned(), "C.UTF-8".to_owned())];
        let (out, _) = run(&me(), Program::Argv(vec!["env".to_owned()]), &env).await;
        let mut names: Vec<&str> = out.lines().map(|l| l.split('=').next().unwrap()).collect();
        // The shell that starts env adds these itself.
        names.retain(|n| !["PWD", "SHLVL", "_"].contains(n));
        names.sort();
        assert_eq!(
            names,
            ["HOME", "LANG", "LOGNAME", "PATH", "SHELL", "TERM", "USER"]
        );
    }

    #[tokio::test]
    async fn pipes_without_terminal_in_own_process_group() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let line = "exec 3</dev/tty || echo no-ctty; \
                    [ \"$(ps -o pgid= -p $$ | tr -d ' ')\" = $$ ] && echo own-group; \
                    env | grep -c ^TERM=; read x; echo got $x >&2; exit 4"
            .to_owned();
        let mut child = spawn(&me(), &Program::Shell(line), &[], Io::Pipes).unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"hi\n").await.unwrap();
        drop(stdin);
        let (mut out, mut err) = (String::new(), String::new());
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .await
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .await
            .unwrap();
        assert_eq!(out, "no-ctty\nown-group\n0\n");
        assert!(err.ends_with("got hi\n"), "{err}");
        assert_eq!(child.wait().await.unwrap().code(), Some(4));
    }

    #[tokio::test]
    async fn signal_ends_process() {
        let line = "kill -TERM $$".to_owned();
        let (_, status) = run(&me(), Program::Shell(line), &[]).await;
        assert_eq!(status.signal(), Some(nix::libc::SIGTERM));
    }

    #[tokio::test]
    async fn login_shell_reads_input() {
        let me = me();
        let Pty { master, slave } = Pty::open(SIZE).unwrap();
        let term = "dumb".to_owned();
        let mut child = spawn(&me, &Program::LoginShell, &[], Io::Pty { slave, term }).unwrap();
        master.write_all(b"echo \"<$0>\"; exit 7\n").await.unwrap();
        let out = output(&master).await;
        let name = login_name(&me.shell);
        assert!(
            out.contains(&format!("<{}>", name.to_str().unwrap())),
            "{out}"
        );
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
    }

    /// As root: `sudo target/debug/deps/stpt-* --ignored as_other_account`.
    #[tokio::test]
    #[ignore = "needs root"]
    async fn as_other_account() {
        let mut nobody = Account::lookup("nobody").unwrap().unwrap();
        // The shell of nobody is nologin: it also refuses an argument vector.
        let (out, status) = run(&nobody, Program::Argv(vec!["id".to_owned()]), &[]).await;
        assert!(
            out.ends_with("This account is currently not available.\r\n"),
            "{out}"
        );
        assert_eq!(status.code(), Some(1));

        nobody.shell = PathBuf::from("/bin/sh");
        let line = "id -u; id -g; id -G; pwd".to_owned();
        let (out, status) = run(&nobody, Program::Shell(line), &[]).await;
        let groups: Vec<String> = nobody.groups.iter().map(|g| g.to_string()).collect();
        // The home of nobody does not exist, so the shell starts in /.
        let expected = format!(
            "stpt: cannot change to the home directory, starting in /\r\n{}\r\n{}\r\n{}\r\n/\r\n",
            nobody.uid,
            nobody.gid,
            groups.join(" ")
        );
        assert_eq!(out, expected);
        assert!(status.success());
    }
}
