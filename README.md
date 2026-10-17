# stpt
Secure terminal access over QUIC: a single program acting as client and server, with Sessions that survive the loss of a connection.

Status: early development. The Client connects to the Server, verifies the Server key, agrees on the protocol version and logs in with the user key; terminals and Sessions are not there yet, so the Client commands end with `not implemented yet`.

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
Every command with `ACCOUNT@HOST` also accepts `--fingerprint SHA256:...` (see Server key) and `-i PATH` (see User key).

- The default port is 843 (UDP). IPv6 addresses go in brackets: `alice@[2001:db8::1]:843`.
- `SESSION` is a Session ID, a unique prefix of it, or a Session name.
- `stpt server` runs the Server, every other command the Client. Server mode is available on Linux only for now; on Windows it comes with terminal support.
- `stpt help COMMAND` shows the options of a command.
- Messages go to standard error. `-v` shows more (`-vv`, `-vvv` even more), `-q` errors only. The Server logs to standard error, which systemd keeps in the journal.

# Private key, public key, fingerprint
Three different texts appear around keys. Do not mix them up.

**Private key** — a file of three lines. Secret: it never leaves its machine; never copy, send or paste it anywhere (also not into `--fingerprint`). Files: `/etc/stpt/server_key` on the Server, `id_ed25519` on the Client.
```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIE…
-----END PRIVATE KEY-----
```

**Public key** — one line of 60 characters starting with `MCowBQYDK2VwAyEA`. Not secret. The user gives it to the administrator, who puts it into the authorized keys of the Account. `openssl pkey -in id_ed25519 -pubout` shows it as its second line.
```
MCowBQYDK2VwAyEAk9YxouLpNL+A/ZjwtDwMeKhGGVbPOnq2vhNQXSwd7Q4=
```

**Fingerprint** — `SHA256:` and 43 characters, computed from a public key (this one from the public key above). Not secret. It is what you compare, in full, and what `--fingerprint` takes. `stpt server --fingerprint` prints the one of the Server key; `stpt trust list` and the Client messages show fingerprints too.
```
SHA256:mskzIR8pKPbyewk8I+WgXjvBQaQbFA9RwVO8MvQ0apc
```

# Server key
The Server proves its identity with a key, as an ssh host key. It creates the key at its first start, in the file `/etc/stpt/server_key` (setting `identity_key`), readable by its owner only; the Server refuses a key file that others can read.

`stpt server --fingerprint` prints the fingerprint of the key (and creates the key if there is none), for example `SHA256:Ab2wRB0yBlg7vMlVGGyOb2TjVLdVNyYGUNUmY/dw6hQ`. Give it to the users of the Server by a channel you trust.

The Client remembers the key of every Server it trusts, in `known_servers` next to its configuration file:
- First connection: the Client shows the fingerprint and asks; type `yes` only if it equals, in full, the fingerprint you got from the administrator. Or pass that fingerprint with `--fingerprint`: then the Client checks it and does not ask. Without a terminal and without `--fingerprint` the Client refuses to connect.
- Later connections: the key must be the remembered one.
- Changed key: the Client refuses to connect and shows both fingerprints. Someone may be intercepting the connection, or the Server got a new key. Only after the administrator confirms the new key, remove the old one with `stpt trust remove HOST[:PORT]` and connect again.

`stpt trust list` shows the remembered Servers and their fingerprints.

# User key
You log in with a key, as with ssh keys; there are no passwords. Create the key once on the Client with OpenSSL (create the `stpt` directory first if it does not exist yet):

| Client | Command |
|---|---|
| Linux | `openssl genpkey -algorithm ed25519 -out ~/.config/stpt/id_ed25519 && chmod 600 ~/.config/stpt/id_ed25519` |
| Windows | `openssl genpkey -algorithm ed25519 -out %APPDATA%\stpt\id_ed25519` |

`-i PATH` uses another key file. On Linux the key file must be readable by you only.

The administrator of the Server decides which keys may log in to which Account (an operating system account on the Server). Show your public key with `openssl pkey -in ~/.config/stpt/id_ed25519 -pubout` and give its second line (it starts with `MCowBQYDK2VwAyEA`) to the administrator; the Client also prints that line when the Server refuses the key.

On the Server, the keys of the Account `alice` are in `/etc/stpt/authorized_keys/alice`, one per line, optionally followed by a label:
```
MCowBQYDK2VwAyEAk9YxouLpNL+A/ZjwtDwMeKhGGVbPOnq2vhNQXSwd7Q4= alice-laptop
```
Only root may change these files: the directory and the files must belong to root and must not be writable by group or others (`chmod 755` for the directory, `644` for the files), otherwise the Server ignores them. A refused login tells the Client nothing about the reason; the Server log has it.

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
authorized_keys = "/etc/stpt/authorized_keys"   # directory of authorized user keys, one file per Account
```
The Client has no settings yet.

# Build
Requires Rust 1.99 or newer, installed with rustup (distribution packages are usually older), and a C compiler: `build-essential` on Debian, the Visual Studio Build Tools (C++) on Windows. The cryptographic library (AWS-LC) is compiled from C.

```
cargo build --release
```

The program is `target/release/stpt` (`stpt.exe` on Windows).

Roadmap of the program: `docs/ROADMAP.md`.
