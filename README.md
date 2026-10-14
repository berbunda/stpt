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
- `stpt server` runs the Server, every other command the Client. Server mode is available on Linux only; on Windows the program is a Client.
- `stpt help COMMAND` shows the options of a command.

# Build
Requires Rust 1.99 or newer, installed with rustup (distribution packages are usually older), and a C linker (`build-essential` on Debian).

```
cargo build --release
```

The program is `target/release/stpt` (`stpt.exe` on Windows).

Roadmap of the program: `docs/ROADMAP.md`.
