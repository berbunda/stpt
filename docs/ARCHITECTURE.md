# STPT Architecture

Protocol specification: https://github.com/berbunda/stpt-protocol/blob/main/specs/PROTOCOL.md

# 1	Structure
Single Cargo package `stpt` (binary crate, edition 2024). Minimum Rust version (`rust-version`): the current stable release, now 1.99; older compilers refuse to build with a clear message.

| Module | Responsibility |
|---|---|
| `src/main.rs` | entry point: parses the command line and runs the command |
| `src/cli.rs` | command line definition and dispatch to a role |
| `src/client.rs` | Client role: all subcommands except `server` |
| `src/server.rs` | Server role: `stpt server` |
| `src/config.rs` | configuration files of both roles |
| `src/destination.rs` | parsing of `account@host[:port]` |

# 2	Command line
- One binary, one explicit subcommand per operation: `server`, `connect`, `exec`, `sessions`, `detach`, `terminate`.
- Commands are parsed and validated but not implemented yet: each prints `not implemented yet`.
- Destination `account@host[:port]`: the last `@` separates the Account (so `user@domain` Accounts work), IPv6 addresses go in brackets, the default port is 843, the Account name is at most 256 bytes (PROTOCOL.md §13.4).
- Session arguments are kept as text (ID, unique ID prefix or name); resolution through the Session list comes with RD004.
- Exit codes: 0 success; 2 command line error (clap); 255 STPT or Connection error. `exec` will return the remote exit code.

# 3	Roles
- The same binary is Client and Server; the subcommand selects the role. `cli::Command` has the variant `Server` and the flattened `Client(ClientCommand)`, so the dispatch in `cli::run` is by role and each role module receives only its own commands.
- Client and Server share only common modules (now `destination`); a role module does not use the other role.
- The command line is the same on every platform. Server mode needs a Unix PTY: on Windows `stpt server` exits with 255 and `Server mode is not available on this platform` (gate G2, until RK006). `server::AVAILABLE` holds the platform check.
- Default listen address `[::]:843`; whether it also accepts IPv4 (dual-stack) is set with the socket in RB001.

# 4	Configuration
- TOML, one file per role, read once at start. `--config PATH` (global option, before or after the subcommand) replaces the default file.
- Default files: Server `/etc/stpt/server.toml`; Client `$XDG_CONFIG_HOME/stpt/config.toml`, else `~/.config/stpt/config.toml` (a relative `XDG_CONFIG_HOME` is ignored, as the XDG specification requires), on Windows `%APPDATA%\stpt\config.toml`.
- A missing default file means built-in defaults; a missing `--config` file, any other read error, a syntax error, a wrong value or an unknown key ends the program with 255 and `stpt: config: PATH: reason` (`deny_unknown_fields`: a misspelt key never falls back to a default silently).
- Precedence: command line, then file, then built-in default.
- Keys: Server `listen`; the Client has none yet (first: RD009). A key is added with the item that uses it.
- The Server checks platform availability (G2) before it reads its configuration.

# 5	Dependencies
| Crate | Purpose | Why |
|---|---|---|
| `clap` (derive) | command line parsing | de facto standard Rust parser: help, error messages and later shell completion (RK003) without own parsing code |
| `serde` (derive) | typed configuration structures | standard Rust (de)serialization framework; also needed later for CBOR messages |
| `toml` (`parse`, `serde` only) | configuration file format | TOML is the usual format of Rust programs (Cargo); errors with line and column; the writer part (`display`) is not compiled in |
