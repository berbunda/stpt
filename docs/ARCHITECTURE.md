# STPT Architecture

Protocol specification: https://github.com/berbunda/stpt-protocol/blob/main/specs/PROTOCOL.md

# 1	Structure
Single Cargo package `stpt` (binary crate, edition 2024). Minimum Rust version (`rust-version`): the current stable release, now 1.99; older compilers refuse to build with a clear message.

| Module | Responsibility |
|---|---|
| `src/main.rs` | entry point: parses the command line, runs the command, reports its error |
| `src/cli.rs` | command line definition and dispatch to a role |
| `src/client.rs` | Client role: all subcommands except `server` |
| `src/server.rs` | Server role: `stpt server` |
| `src/config.rs` | configuration files of both roles |
| `src/destination.rs` | parsing of `account@host[:port]` |
| `src/error.rs` | error type ending the program, exit codes |
| `src/logging.rs` | log levels and log output |
| `src/quic.rs` | QUIC transport: Endpoints, transport parameters, sockets |
| `src/tls.rs` | TLS 1.3 profile, Server key, verification of the Server key |

# 2	Command line
- One binary, one explicit subcommand per operation: `server`, `connect`, `exec`, `sessions`, `detach`, `terminate`.
- Commands are parsed and validated. `server` accepts Connections (§6); the Client commands are not implemented yet and print `not implemented yet`.
- Destination `account@host[:port]`: the last `@` separates the Account (so `user@domain` Accounts work), IPv6 addresses go in brackets, the default port is 843, the Account name is at most 256 bytes (PROTOCOL.md §13.4).
- Session arguments are kept as text (ID, unique ID prefix or name); resolution through the Session list comes with RD004.
- Exit codes: 0 success; 2 command line error (clap); 255 STPT or Connection error. `exec` will return the remote exit code.
- Global options `--config`, `-v`/`--verbose` (repeatable), `-q`/`--quiet` are accepted before or after the subcommand. clap does not detect a conflict of global options given on different levels (`-q server -v`), so `Cli::validate` checks `-q` with `-v` after parsing.

# 3	Roles
- The same binary is Client and Server; the subcommand selects the role. `cli::Command` has the variant `Server` and the flattened `Client(ClientCommand)`, so the dispatch in `cli::run` is by role and each role module receives only its own commands.
- Client and Server share only common modules (now `destination`, `quic`, `tls`); a role module does not use the other role.
- The command line is the same on every platform. Server mode needs a Unix PTY: on Windows `stpt server` exits with 255 and `Server mode is not available on this platform` (gate G2, until RC008). `server::AVAILABLE` holds the platform check.
- Default listen address `[::]:843`, dual-stack (§6).

# 4	Configuration
- TOML, one file per role, read once at start. `--config PATH` (global option, before or after the subcommand) replaces the default file.
- Default files: Server `/etc/stpt/server.toml`; Client `$XDG_CONFIG_HOME/stpt/config.toml`, else `~/.config/stpt/config.toml` (a relative `XDG_CONFIG_HOME` is ignored, as the XDG specification requires), on Windows `%APPDATA%\stpt\config.toml`.
- A missing default file means built-in defaults; a missing `--config` file, any other read error, a syntax error, a wrong value or an unknown key ends the program with 255 and `stpt: config: PATH: reason` (`deny_unknown_fields`: a misspelt key never falls back to a default silently).
- Precedence: command line, then file, then built-in default.
- The Client has no keys yet (first: RD009). A key is added with the item that uses it.
- The Server checks platform availability (G2) before it reads its configuration.
- Keys: Server `listen`, `log_level`.

# 5	Errors and logging
- A role returns `Result<ExitCode, error::Error>`. `main` prints an error once as `stpt: <error>` on standard error and exits with `Error::exit_code` (now always 255). Command line errors are clap's (exit 2). Lower modules have their own error types (`config::Error`, `quic::Error`), converted with `From`.
- The final error is printed directly, not as a log event: it is also shown when the configuration fails, before logging starts, and under `-q`.
- Log events: `tracing` with a `tracing-subscriber` fmt subscriber on standard error, installed once after the configuration is read; no ANSI colours, no log files (under systemd standard error goes to the journal, RK001).
- Level: `-q` error; `-v` info, `-vv` debug, `-vvv` trace; else the Server's `log_level`; else Client warn, Server info.
- Format: Client `LEVEL message fields`; Server adds UTC time and module (`2026-10-14T10:40:00Z DEBUG stpt::server: listen address listen=[::]:843`).
- Peer input in the log: only as `?` fields (Debug escaping of line breaks and control characters), so a peer cannot forge lines or inject terminal sequences; `%` (Display) only for values the program produced or the local user gave. Secrets are never logged.

# 6	Transport
PROTOCOL.md §6–§8.2, §13.3. `quinn` (QUIC) over `rustls` (TLS 1.3) with the `aws-lc-rs` crypto provider.

- Async: one multi-threaded `tokio` runtime per process (`quic::runtime`), created by the role; the rest of the program is synchronous.
- Sockets: created with `socket2`. `[::]` is set dual-stack explicitly (`IPV6_V6ONLY` off), so it does not depend on the system default (Linux `net.ipv6.bindv6only`, Windows on by default); a specific address listens on that address only. The Client binds the unspecified address of the Server's family, port 0.
- QUIC: version 1 only (`EndpointConfig::supported_versions`). Transport parameters: no unidirectional streams; bidirectional stream limit for the peer 1 on the Server (the control stream), 0 on the Client, raised only after authentication (RB006); no datagrams; idle timeout 60 s; Client keep-alive PING after 15 s idle; Server migration on.
- TLS (`tls`): provider reduced to TLS 1.3 with AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM and the groups X25519MLKEM768, X25519 (this order); ALPN `stpt` only, a Client offering no or another ALPN fails the handshake; no client certificates, no 0-RTT, no session resumption (no tickets, no session cache on either side). SNI: a DNS name is sent, an IP address is not (rustls `ServerName`).
- Hybrid group: rustls selects the first group in the Client's `supported_groups` that the Server supports. The Server cert resolver (`ServerIdentity`) therefore aborts the handshake when the Client lists X25519 before X25519MLKEM768, so X25519 is negotiated only with Clients without the hybrid group (PROTOCOL.md §6.2).
- Server key: Ed25519 Raw Public Key (RFC 7250), generated with `aws-lc-rs` at every start and held in memory only; persistence, fingerprint and trust store come with RB003. The Server logs a warning that the key is temporary.
- Client verification (`ExpectedKey`): only Raw Public Keys, the presented SubjectPublicKeyInfo must equal the expected key byte for byte, signature scheme Ed25519 only. The Client side (`quic::connect`) is used by tests only until the Client has a source for the expected key (RB003).
- Server Connection lifecycle: accept, handshake, log `Connection established` with the remote address, keep the Connection until the Client closes it or the idle timeout expires, log the close reason. Handshake failures are logged with their reason (info). HELLO and its deadline come with RB004, the control stream with RB007. The Server runs until it is killed; graceful shutdown comes later.
- `rustls` is built without its `logging` feature and `quinn` without `log`, so no `log` bridge is needed; handshake errors reach the log through the `quinn` error values.

# 7	Dependencies
| Crate | Purpose | Why |
|---|---|---|
| `clap` (derive) | command line parsing | de facto standard Rust parser: help, error messages and later shell completion (RK003) without own parsing code |
| `serde` (derive) | typed configuration structures | standard Rust (de)serialization framework; also needed later for CBOR messages |
| `tracing` | log events | the logging API of the async Rust stack: `quinn` (RB001) logs through it; spans will give each line its Connection and Session |
| `tracing-subscriber` (`fmt`, `std` only) | log output | the standard `tracing` output; without `ansi`, `env-filter`, `tracing-log`, so no colour, regex or `log` bridge code is compiled in |
| `toml` (`parse`, `serde` only) | configuration file format | TOML is the usual format of Rust programs (Cargo); errors with line and column; the writer part (`display`) is not compiled in |
| `quinn` (`runtime-tokio`, `rustls-aws-lc-rs`) | QUIC | the established Rust QUIC implementation (DECISIONS §5); without default features: no `ring`, no platform certificate verifier (no X.509), no `log` |
| `rustls` (`aws_lc_rs`, `std`) | TLS 1.3 | memory-safe TLS used by `quinn`; supports Raw Public Keys and X25519MLKEM768; without TLS 1.2 and `logging` |
| `aws-lc-rs` | Ed25519 key generation | the crypto provider of `rustls` already, so no further library; the only one of the `rustls` providers with X25519MLKEM768. Built from C (AWS-LC): a C compiler is needed |
| `tokio` (`rt-multi-thread`, `time`) | async runtime | the runtime `quinn` runs on |
| `socket2` | UDP socket options | explicit dual-stack; already used inside `tokio` and `quinn` |
