# stpt
Secure terminal access over QUIC: a single program acting as client and server, with Sessions that survive the loss of a connection.

Status: early development. The commands below are recognised, but none is implemented yet.

```
stpt server [--listen ADDR:PORT]
stpt connect ACCOUNT@HOST[:PORT] [--name NAME | --attach SESSION [--takeover] [--read-only]]
stpt exec ACCOUNT@HOST[:PORT] [--no-shell] COMMAND...
stpt sessions ACCOUNT@HOST[:PORT]
stpt detach ACCOUNT@HOST[:PORT] SESSION (--all | --id ATTACHMENT)
stpt terminate ACCOUNT@HOST[:PORT] SESSION [--force]
```

- The default port is 843 (UDP). IPv6 addresses go in brackets: `alice@[2001:db8::1]:843`.
- `SESSION` is a Session ID, a unique prefix of it, or a Session name.
- `stpt server` runs the Server, every other command the Client. Server mode is available on Linux only for now; on Windows it comes with terminal support.
- `stpt help COMMAND` shows the options of a command.
- Messages go to standard error. `-v` shows more (`-vv`, `-vvv` even more), `-q` errors only. The Server logs to standard error, which systemd keeps in the journal.

# Configuration
TOML files, optional; `--config PATH` uses another file.

| Role | Default file |
|---|---|
| Server | `/etc/stpt/server.toml` |
| Client, Linux | `~/.config/stpt/config.toml` (`$XDG_CONFIG_HOME/stpt/config.toml` if set) |
| Client, Windows | `%APPDATA%\stpt\config.toml` |

Command line options override the file. Unknown keys and invalid values are errors.

Server settings:
```toml
listen = "[::]:843"   # address and UDP port; IPv6 addresses in brackets
log_level = "info"    # error, warn, info, debug or trace; -v and -q override it
```
The Client has no settings yet.

# Build
Requires Rust 1.99 or newer, installed with rustup (distribution packages are usually older), and a C linker (`build-essential` on Debian).

```
cargo build --release
```

The program is `target/release/stpt` (`stpt.exe` on Windows).

Roadmap of the program: `docs/ROADMAP.md`.
