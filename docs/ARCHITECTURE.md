# STPT Architecture

Protocol specification: https://github.com/berbunda/stpt-protocol/blob/main/specs/PROTOCOL.md

# 1	Structure
Single Cargo package `stpt` (binary crate, edition 2024).

| Module | Responsibility |
|---|---|
| `src/main.rs` | entry point: parses the command line and runs the command |
| `src/cli.rs` | command line definition and dispatch |
| `src/destination.rs` | parsing of `account@host[:port]` |

# 2	Command line
- One binary, one explicit subcommand per operation: `server`, `connect`, `exec`, `sessions`, `detach`, `terminate`. Client and Server mode are selected by the subcommand.
- Commands are parsed and validated but not implemented yet: each prints `not implemented yet`.
- Destination `account@host[:port]`: the last `@` separates the Account (so `user@domain` Accounts work), IPv6 addresses go in brackets, the default port is 843, the Account name is at most 256 bytes (PROTOCOL.md §13.4).
- Session arguments are kept as text (ID, unique ID prefix or name); resolution through the Session list comes with RD004.
- Exit codes: 0 success; 2 command line error (clap); 255 STPT or Connection error. `exec` will return the remote exit code.

# 3	Dependencies
| Crate | Purpose | Why |
|---|---|---|
| `clap` (derive) | command line parsing | de facto standard Rust parser: help, error messages and later shell completion (RK003) without own parsing code |
