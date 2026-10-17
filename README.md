# stpt
Secure terminal access over QUIC: a single program acting as client and server, with Sessions that survive the loss of a connection.

Status: early development. The Client connects to the Server and verifies the Server key; nothing else happens on the Connection yet, so the Client commands end with `not implemented yet`.

```
stpt server [--listen ADDR:PORT] [--fingerprint]
stpt connect ACCOUNT@HOST[:PORT] [--name NAME | --attach SESSION [--takeover] [--read-only]]
stpt exec ACCOUNT@HOST[:PORT] [--no-shell] COMMAND...
stpt sessions ACCOUNT@HOST[:PORT]
stpt detach ACCOUNT@HOST[:PORT] SESSION (--all | --id ATTACHMENT)
stpt terminate ACCOUNT@HOST[:PORT] SESSION [--force]
stpt trust list
stpt trust remove HOST[:PORT]
```
Every command with `ACCOUNT@HOST` also accepts `--fingerprint SHA256:...` (see Server key).

- The default port is 843 (UDP). IPv6 addresses go in brackets: `alice@[2001:db8::1]:843`.
- `SESSION` is a Session ID, a unique prefix of it, or a Session name.
- `stpt server` runs the Server, every other command the Client. Server mode is available on Linux only for now; on Windows it comes with terminal support.
- `stpt help COMMAND` shows the options of a command.
- Messages go to standard error. `-v` shows more (`-vv`, `-vvv` even more), `-q` errors only. The Server logs to standard error, which systemd keeps in the journal.

# Server key
The Server proves its identity with a key, as an ssh host key. It creates the key at its first start, in the file `/etc/stpt/server_key` (setting `identity_key`), readable by its owner only; the Server refuses a key file that others can read.

`stpt server --fingerprint` prints the fingerprint of the key (and creates the key if there is none), for example `SHA256:Ab2wRB0yBlg7vMlVGGyOb2TjVLdVNyYGUNUmY/dw6hQ`. Give it to the users of the Server by a channel you trust.

The Client remembers the key of every Server it trusts, in `known_servers` next to its configuration file:
- First connection: the Client shows the fingerprint and asks; type `yes` only if it equals, in full, the fingerprint you got from the administrator. Or pass that fingerprint with `--fingerprint`: then the Client checks it and does not ask. Without a terminal and without `--fingerprint` the Client refuses to connect.
- Later connections: the key must be the remembered one.
- Changed key: the Client refuses to connect and shows both fingerprints. Someone may be intercepting the connection, or the Server got a new key. Only after the administrator confirms the new key, remove the old one with `stpt trust remove HOST[:PORT]` and connect again.

`stpt trust list` shows the remembered Servers and their fingerprints.

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
listen = "[::]:843"   # address and UDP port; IPv6 addresses in brackets; [::] also accepts IPv4
log_level = "info"    # error, warn, info, debug or trace; -v and -q override it
identity_key = "/etc/stpt/server_key"   # Server key file, created if missing
```
The Client has no settings yet.

# Build
Requires Rust 1.99 or newer, installed with rustup (distribution packages are usually older), and a C compiler: `build-essential` on Debian, the Visual Studio Build Tools (C++) on Windows. The cryptographic library (AWS-LC) is compiled from C.

```
cargo build --release
```

The program is `target/release/stpt` (`stpt.exe` on Windows).

Roadmap of the program: `docs/ROADMAP.md`.
