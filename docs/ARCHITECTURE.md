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
| `src/destination.rs` | parsing of `account@host[:port]` and `host[:port]` |
| `src/auth.rs` | user authentication messages, channel binding, user key |
| `src/authorized.rs` | authorized keys of the Accounts, uniform Server decision |
| `src/cbor.rs` | strict CBOR codec of the STPT subset |
| `src/error.rs` | error type ending the program, exit codes |
| `src/hello.rs` | HELLO messages, version selection, capabilities, limits, GREASE |
| `src/identity.rs` | Server Identity: key pair and key file, public key, fingerprint |
| `src/logging.rs` | log levels and log output |
| `src/quic.rs` | QUIC transport: Endpoints, transport parameters, sockets |
| `src/tls.rs` | TLS 1.3 profile, verification of the Server key |
| `src/trust.rs` | trust store of the Client |
| `src/wire.rs` | frames, messages, message types, error codes |

# 2	Command line
- One binary, one explicit subcommand per operation: `server`, `connect`, `exec`, `sessions`, `detach`, `terminate`, `trust list`, `trust remove`.
- `server` accepts Connections (§6); `server --fingerprint` prints the fingerprint of the Server key and exits (§7). The Client commands with a destination load the user key, establish a Connection, verify the Server key (§7), exchange HELLO (§8) and authenticate (§9), then close it regularly and print `not implemented yet`. `trust` manages the trust store.
- The destination, `--fingerprint SHA256:...` and `-i/--identity PATH` (user key) form `cli::Remote`, flattened into every Client command with a destination.
- Destination `account@host[:port]`: the last `@` separates the Account (so `user@domain` Accounts work), IPv6 addresses go in brackets, the default port is 843, the Account name is at most 256 bytes (PROTOCOL.md §13.4).
- Server address (`destination::Address`, also `trust remove HOST[:PORT]`): normalized at parsing, so equal addresses compare equal: DNS names in lower case, IP addresses in canonical form (`[0::1]` = `[::1]`). A host with a space, control character or bracket is refused, so it cannot break a trust store line.
- Session arguments are kept as text (ID, unique ID prefix or name); resolution through the Session list comes with RD004.
- Exit codes: 0 success; 2 command line error (clap); 255 STPT or Connection error. `exec` will return the remote exit code.
- Global options `--config`, `-v`/`--verbose` (repeatable), `-q`/`--quiet` are accepted before or after the subcommand. clap does not detect a conflict of global options given on different levels (`-q server -v`), so `Cli::validate` checks `-q` with `-v` after parsing.

# 3	Roles
- The same binary is Client and Server; the subcommand selects the role. `cli::Command` has the variant `Server` and the flattened `Client(ClientCommand)`, so the dispatch in `cli::run` is by role and each role module receives only its own commands.
- Client and Server share only common modules (now `destination`, `identity`, `quic`, `tls`); a role module does not use the other role.
- The command line is the same on every platform. Server mode needs a Unix PTY: on Windows `stpt server` exits with 255 and `Server mode is not available on this platform` (gate G2, until RC008). `server::AVAILABLE` holds the platform check.
- Default listen address `[::]:843`, dual-stack (§6).

# 4	Configuration
- TOML, one file per role, read once at start. `--config PATH` (global option, before or after the subcommand) replaces the default file.
- Default files: Server `/etc/stpt/server.toml`; Client `$XDG_CONFIG_HOME/stpt/config.toml`, else `~/.config/stpt/config.toml` (a relative `XDG_CONFIG_HOME` is ignored, as the XDG specification requires), on Windows `%APPDATA%\stpt\config.toml`.
- A missing default file means built-in defaults; a missing `--config` file, any other read error, a syntax error, a wrong value or an unknown key ends the program with 255 and `stpt: config: PATH: reason` (`deny_unknown_fields`: a misspelt key never falls back to a default silently).
- Precedence: command line, then file, then built-in default.
- The Client has no keys yet (first: RD009). A key is added with the item that uses it. The Client configuration directory also holds the trust store `known_servers` (§7); `config::client_dir` gives the directory.
- The Server checks platform availability (G2) before it reads its configuration.
- Keys: Server `listen`, `log_level`, `identity_key` (Server key file, default `/etc/stpt/server_key`), `authorized_keys` (directory, default `/etc/stpt/authorized_keys`). The Client's default user key is `id_ed25519` in its configuration directory.

# 5	Errors and logging
- A role returns `Result<ExitCode, error::Error>`. `main` prints an error once as `stpt: <error>` on standard error and exits with `Error::exit_code` (now always 255). Command line errors are clap's (exit 2). Lower modules have their own error types (`config::Error`, `quic::Error`, `identity::KeyFileError`, `trust::Error`), converted with `From`. Errors of the Server key check are multi-line (§7). A protocol failure found by the Client (`wire::Failure`: code and local reason) is `Error::Protocol`, printed as `stpt: protocol: <reason> (<CODE>)`; a close by the Server is a transport error printed with the code name (`stpt: transport: closed by the peer: VERSION_NEGOTIATION_FAILED`).
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
- Server key: Ed25519 Raw Public Key (RFC 7250) of the Server Identity (§7).
- Client verification (`tls::ServerKeyCheck`, a rustls `ServerCertVerifier`): only Raw Public Keys, signature scheme Ed25519 only, the handshake signature verified with the presented key. The verifier decides on the presented SubjectPublicKeyInfo with the stored key and the `--fingerprint` (`Expected`) and records the key with its `Verdict`: `Trusted` lets the handshake go on; `Unknown`, `Changed`, `Mismatch` abort it, and the Client reads the verdict to report the reason (§7).
- Client Endpoint: `quic::client` binds once per command; `quic::connect` may run on it several times (reconnect after a confirmation, §7). A regular close sends NO_ERROR (`quic::NO_ERROR`) and waits until the Endpoint is idle, so the Server sees the close.
- Server Connection lifecycle: accept, TLS handshake (failures logged with their reason, info), HELLO (§8), then wait for user authentication until its deadline; log the close with the remote address and either the Client's close reason or the Server's code and exact reason. The Server runs until it is killed; graceful shutdown comes later.
- `rustls` is built without its `logging` feature and `quinn` without `log`, so no `log` bridge is needed; handshake errors reach the log through the `quinn` error values.
- Close reasons: `stpt` closes with an empty reason phrase (`quic::NO_ERROR`, `b""`). After a failed TLS handshake `quinn` itself sends the `rustls` error text in the transport close (e.g. `invalid peer certificate: UnknownIssuer`); quinn has no option to suppress it, and PROTOCOL.md §13.1 allows it. A received reason phrase is never acted on; it is shown only escaped (`quic::Error` writes it with Debug escaping, as quinn's own Display writes it unchanged), so a peer cannot put line breaks or terminal control sequences into the Client's error message.

# 7	Server Identity and trust store
PROTOCOL.md §9.

- Server key file (`identity`): Ed25519 private key, PEM PKCS#8 (`-----BEGIN PRIVATE KEY-----`, as `openssl genpkey -algorithm ed25519` writes it, so an administrator can also supply one). Default `/etc/stpt/server_key`, setting `identity_key`.
- Created at the first start if missing: parent directory created, file opened with `create_new` and mode 0600 (never replaces a file; if another process created it meanwhile, that file is read), key generated by `aws-lc-rs`, written and synced. The Server logs `Server key created` with path and fingerprint; at every start it logs `Server key` with path and fingerprint.
- Loading: on Unix the open file must not be accessible by group or others (`permissions 644 are too open … (chmod 600)`), checked on the open handle; the key must be PKCS#8 Ed25519 (another algorithm or a damaged file is an error naming the file). Errors end the Server before it binds its socket.
- `stpt server --fingerprint` loads or creates the key, prints the fingerprint on standard output and exits; it needs the same rights as the Server.
- Fingerprint (`identity::Fingerprint`): SHA-256 over the SubjectPublicKeyInfo, text `SHA256:` + base64 without padding. Parsing accepts only the full form (no prefix, no padding, no other case), so a shortened fingerprint is refused by the command line.
- Trust store (`trust`): file `known_servers` in the Client configuration directory (`~/.config/stpt/`, `%APPDATA%\stpt\`). One entry per line, `HOST:PORT KEY`, KEY = base64 of the SubjectPublicKeyInfo (with padding); empty lines and `#` comments are kept. A syntax error or two different keys for one address is an error naming file and line (fail closed); the same entry twice is accepted. Changes rewrite the whole file into a temporary file and rename it over the old one. A new file starts with a comment explaining the format and `stpt trust remove`.
- Client connect (`client::connect`), with the stored key and `--fingerprint`:
  - Stored key or fingerprint known: the presented key must equal the stored key and match the fingerprint, whichever is given. A key verified by `--fingerprint` for an address without entry is stored.
  - First contact (neither): the handshake is aborted, the Client shows the fingerprint and asks; only `yes` (any case) confirms. After a confirmation the key is stored and the Client connects again expecting exactly that key. No Server deadline (CLIENT_HELLO 10 s, RB004) runs while the user reads the fingerprint, and the second handshake proves that the Server holds the key.
  - Asking needs a terminal on standard input and standard error; otherwise the Client ends with the fingerprint and the advice to use `--fingerprint`.
  - Changed key or fingerprint mismatch: the Client ends with both fingerprints in full; for a changed key it names `stpt trust remove HOST:PORT`, which is the only way to replace an entry (no prompt offers to accept the new key).
- The host is resolved with the system resolver; only the first address is used for now.
- Not yet: key rotation (PI003/RI004), hashing of host names in the trust store, system-wide trust store.

# 8	Messages and HELLO
PROTOCOL.md §7, §8.1, §10, §11, §13.

- CBOR (`cbor`): own codec of the subset STPT uses (`Value`: unsigned and negative integers, byte and text strings, arrays, maps, booleans, null). The encoder writes deterministic encoding: shortest arguments, definite lengths, map keys sorted bytewise by their encoding. The decoder accepts only that: it rejects indefinite lengths, tags, floats, other simple values, reserved additional information, arguments longer than needed, map keys out of order or duplicate, invalid UTF-8, nesting deeper than 16 (the message array is depth 1) and bytes after the item. A claimed array, map or string length larger than the remaining input is refused before any allocation.
- Frames (`wire`): QUIC varint length (any valid form accepted, shortest written), then one CBOR item. A frame of length 0 is a protocol violation; a length over the receiver limit (65535, the minimum and default of §13.4; `stpt` announces no larger one) is refused with LIMIT_EXCEEDED before the payload is read. The end of a stream inside a frame is a protocol violation. `Message` is `[type, {* int => any}]`; unknown body keys are kept and never asked for.
- `wire::Failure` (error code and reason) is a locally found reason to close; the peer gets only the code with an empty reason phrase (PROTOCOL.md §13.1), the reason goes to the Server log or the Client's error message. `wire::Code` holds the codes of §13.2 and their names.
- HELLO (`hello`): wire version 0xFF000001 only. The Client offers it plus one random GREASE version (0x?A?A?A?A, repeated digit) and one random GREASE capability with parameter null; no capabilities are defined yet, so the Server selects none. Limits are sent only when they differ from the default. The Server selects the highest common final version, else the highest common draft version, never GREASE; none: VERSION_NEGOTIATION_FAILED. SERVER_HELLO lists method 1 (`publickey-ed25519`).
- Validation: CLIENT_HELLO needs a non-empty list of uint versions; capabilities a map with uint ids; limits a map with integer keys and a message size of at least 65535. The Client checks SERVER_HELLO: a version it offered and not GREASE, only capabilities it offered and not GREASE, a non-empty list of methods. Every violation is PROTOCOL_VIOLATION.
- Server sequence (`server::serve_connection`): accept the control stream and read CLIENT_HELLO within 10 s (TIMEOUT); the first message must be CLIENT_HELLO; answer SERVER_HELLO; Established; then user authentication (§9). The end or a reset of the control stream is PROTOCOL_VIOLATION at any time. Deadlines are `server::Deadlines` (shorter in tests). An internal `End` (Connection lost, or a `Failure` the Server closes with) lets every step use `?`.
- Client sequence (`client::Connection::hello`): open the control stream, send CLIENT_HELLO, read SERVER_HELLO within 10 s (TIMEOUT, PROTOCOL.md §13.3), check it, including that method 1 is offered. The Client keeps both directions of the control stream until it closes the Connection: dropping a quinn stream sends FIN, which the Server would treat as a violation. A failed step (`Connection::failed`) closes with the code of the failure.
- Not yet (RB007): the control stream after authentication, message dispatch by Connection state, stream priority.

# 9	User authentication
PROTOCOL.md §12, §13.3, §13.4.

- User key (`auth::UserKey`): Ed25519, PEM PKCS#8 as `openssl genpkey -algorithm ed25519` writes it (v1 and v2 accepted), read by `identity::read_private_key` with the same owner-only check on Unix as the Server key. Default `id_ed25519` in the Client configuration directory, `-i/--identity PATH` for another file. It is loaded before the Client connects; a missing file ends with the openssl command that creates it (`&& chmod 600` on Unix). `stpt keygen` comes with RI001.
- AUTH_REQUEST (`auth`): method 1, Account (at most 256 bytes, else LIMIT_EXCEEDED), raw 32-byte key, 64-byte signature over the deterministic CBOR of `["STPT user authentication", exporter, method, Account, key]`. The exporter value is the TLS exporter of the Connection (`quinn::Connection::export_keying_material`, label `EXPORTER-STPT-user-auth`, empty context, 32 bytes); each side computes it itself. Verification: `aws-lc-rs` Ed25519 (RFC 8032).
- Authorized keys (`authorized`): directory `authorized_keys` (default `/etc/stpt/authorized_keys`), one file per Account named like the Account, kept by the administrator. Line: base64 of the key's SubjectPublicKeyInfo (second line of `openssl pkey -pubout`), optional label of 1–64 bytes; `#` comments. Directory and file must be owned by root or by the Server's own user and not writable by group or others, the file must be a regular file; otherwise, or with an invalid line, the file is ignored (fail closed) and the reason logged. An Account name that is not a plain file name (`/`, `\`, `.`, `..`, control characters) is treated as an unknown Account.
- Accounts: `authorized::SystemAccounts` asks the system user database (`getpwnam` through `nix`); tests use their own `Accounts`.
- Decision (`Authorizer::decide`, in `spawn_blocking`, as `getpwnam` and file reading block): signature verification, Account lookup and reading the keys file all run, whichever fails; the decision is made once after them. The exact reason (invalid signature, no such Account, keys file missing, unsafe or invalid, key not listed) goes to the Server log with Account (Debug-escaped) and key fingerprint; the Client gets AUTH_RESULT false.
- Server sequence (`server::authenticate`): AUTH_REQUEST after AUTH_REQUEST until the authentication deadline (60 s); another message type before authentication, or an unoffered method, is PROTOCOL_VIOLATION. A failure is answered no earlier than 300 ms (`Deadlines::failure_delay`) after its AUTH_REQUEST, so the response time does not depend on the reason; the 6th failure closes with AUTH_FAILED instead of a result.
- Authenticated Connection: the Server logs Account, key fingerprint and label, raises the bidirectional stream limit to 1 + 10 (§8.2, §14.5) and rejects every new stream with CHANNEL_REJECTED (RESET_STREAM and STOP_SENDING) until Channels exist (Tier RC). On the control stream a further AUTH_REQUEST or CLIENT_HELLO is PROTOCOL_VIOLATION; any other message closes with INTERNAL_ERROR (`not implemented yet`, RB007 and Tier RD).
- Client (`client::Connection::authenticate`): one key, one AUTH_REQUEST, AUTH_RESULT within 10 s (TIMEOUT). Refused: the Client closes regularly and ends with the key fingerprint and its authorized keys line for the administrator.

# 10	Dependencies
| Crate | Purpose | Why |
|---|---|---|
| `clap` (derive) | command line parsing | de facto standard Rust parser: help, error messages and later shell completion (RK003) without own parsing code |
| `serde` (derive) | typed configuration structures | standard Rust (de)serialization framework; also needed later for CBOR messages |
| `tracing` | log events | the logging API of the async Rust stack: `quinn` (RB001) logs through it; spans will give each line its Connection and Session |
| `tracing-subscriber` (`fmt`, `std` only) | log output | the standard `tracing` output; without `ansi`, `env-filter`, `tracing-log`, so no colour, regex or `log` bridge code is compiled in |
| `toml` (`parse`, `serde` only) | configuration file format | TOML is the usual format of Rust programs (Cargo); errors with line and column; the writer part (`display`) is not compiled in |
| `quinn` (`runtime-tokio`, `rustls-aws-lc-rs`) | QUIC | the established Rust QUIC implementation (DECISIONS §5); without default features: no `ring`, no platform certificate verifier (no X.509), no `log` |
| `rustls` (`aws_lc_rs`, `std`) | TLS 1.3 | memory-safe TLS used by `quinn`; supports Raw Public Keys and X25519MLKEM768; without TLS 1.2 and `logging` |
| `aws-lc-rs` | Ed25519 key generation, SHA-256 of fingerprints | the crypto provider of `rustls` already, so no further library; the only one of the `rustls` providers with X25519MLKEM768. Built from C (AWS-LC): a C compiler is needed |
| `tokio` (`rt-multi-thread`, `time`) | async runtime | the runtime `quinn` runs on |
| `socket2` | UDP socket options | explicit dual-stack; already used inside `tokio` and `quinn` |
| `nix` (`user` only; Unix only) | Account lookup (`getpwnam_r`), file owner check (`geteuid`) | safe wrappers of the Unix calls instead of own `unsafe` FFI; needed later for PTY, processes and signals (Tier RC) |
| `base64` (`std` only) | fingerprints, PEM key file, trust store | the standard Rust base64 crate; strict decoding (no non-canonical trailing bits); without the default `simd-unsafe` feature |
