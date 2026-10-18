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
| `src/session.rs` | Server side of a terminal Channel: Session start, input and output, exit (Unix) |
| `src/config.rs` | configuration files of both roles |
| `src/console.rs` | local terminal of the Client: raw mode, window size, input and output |
| `src/control.rs` | control stream rules: permitted messages per state, requests, CHANNEL_OPEN |
| `src/destination.rs` | parsing of `account@host[:port]` and `host[:port]` |
| `src/auth.rs` | user authentication messages, channel binding, user key |
| `src/authorized.rs` | authorized keys of the Accounts, uniform Server decision |
| `src/cbor.rs` | strict CBOR codec of the STPT subset |
| `src/error.rs` | error type ending the program, exit codes |
| `src/hello.rs` | HELLO messages, version selection, capabilities, limits, GREASE |
| `src/identity.rs` | Server Identity: key pair and key file, public key, fingerprint |
| `src/logging.rs` | log levels and log output |
| `src/process.rs` | processes of a Session: Account, login shell or command (Unix) |
| `src/pty.rs` | pseudo-terminals of the Server (Unix) |
| `src/quic.rs` | QUIC transport: Endpoints, transport parameters, sockets |
| `src/terminal.rs` | terminal Channel messages: opening parameters, TERMINAL_ATTACHED, data, exit status, signal ids |
| `src/tls.rs` | TLS 1.3 profile, verification of the Server key |
| `src/trust.rs` | trust store of the Client |
| `src/wire.rs` | frames, messages, message types, error codes |

# 2	Command line
- One binary, one explicit subcommand per operation: `server`, `connect`, `exec`, `sessions`, `detach`, `terminate`, `trust list`, `trust remove`.
- `server` accepts Connections (§6); `server --fingerprint` prints the fingerprint of the Server key and exits (§7). The Client commands with a destination load the user key, establish a Connection, verify the Server key (§7), exchange HELLO (§8) and authenticate (§9). `connect` and `exec` then run a terminal Channel (§10); `connect --attach`, `sessions`, `detach` and `terminate` close the Connection regularly and print `not implemented yet` (Tier RD). `trust` manages the trust store.
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

- Async: one multi-threaded `tokio` runtime per process (`quic::runtime`), created by the role; Connections and PTY masters (§10) run on it, the rest of the program is synchronous.
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
- Server sequence (`server::serve_connection`): accept the control stream and read CLIENT_HELLO within 10 s (TIMEOUT); the first message must be CLIENT_HELLO; answer SERVER_HELLO; Established; then user authentication (§9) and the Authenticated control stream (below). The end or a reset of the control stream is PROTOCOL_VIOLATION at any time. Deadlines are `server::Deadlines` (shorter in tests). An internal `End` (Connection lost, or a `Failure` the Server closes with) lets every step use `?`.
- Client sequence (`client::Connection::hello`): open the control stream, send CLIENT_HELLO, read SERVER_HELLO within 10 s (TIMEOUT, PROTOCOL.md §13.3), check it, including that method 1 is offered. The Client keeps both directions of the control stream until it closes the Connection: dropping a quinn stream sends FIN, which the Server would treat as a violation. A failed step (`Connection::failed`) closes with the code of the failure.
- Permitted messages (`control::check`, PROTOCOL.md §3.1, §8.1, §11.4): one table of the control messages, their sender and the Connection state they belong to: CLIENT_HELLO and SERVER_HELLO in Handshaking, AUTH_REQUEST and AUTH_RESULT in Established, the requests (SESSION_TERMINATE, SESSION_DETACH, SESSION_LIST) and REQUEST_RESULT in Authenticated. Every message read from the control stream is checked against it, by the Server with sender Client and by the Client with sender Server. A message out of state or direction, a Channel message (CHANNEL_OPEN, TERMINAL_*) on the control stream, or an unknown type is PROTOCOL_VIOLATION.
- Requests (§8.4): on the Authenticated control stream the Server reads requests in a loop; each needs a uint request ID (key 0, else PROTOCOL_VIOLATION) and gets exactly one REQUEST_RESULT with the ID and an error code. The operations come with Tier RD; until then every result carries INTERNAL_ERROR and the Connection stays open. Duplicate IDs and the limit of outstanding requests (16) come with the first request that does not answer at once. The Client sends no requests yet.
- Channels (§8.3): after authentication the Server accepts streams and reads each one's first message (limit 65535). CHANNEL_OPEN of kind 1: terminal Channel (§10); another kind is rejected with CHANNEL_REJECTED (RESET_STREAM and STOP_SENDING), and the Connection stays. Another first message, an invalid one, or FIN before CHANNEL_OPEN closes the Connection with PROTOCOL_VIOLATION; a stream reset before CHANNEL_OPEN is ignored. Each stream is handled in its own task; the stream limit (10) bounds them.
- Priority: both sides set send priority 1 on the control stream (`control::CONTROL_PRIORITY`); Channel streams keep 0, so control messages are not queued behind Channel data (§8.1).

# 9	User authentication
PROTOCOL.md §12, §13.3, §13.4.

- User key (`auth::UserKey`): Ed25519, PEM PKCS#8 as `openssl genpkey -algorithm ed25519` writes it (v1 and v2 accepted), read by `identity::read_private_key` with the same owner-only check on Unix as the Server key. Default `id_ed25519` in the Client configuration directory, `-i/--identity PATH` for another file. It is loaded before the Client connects; a missing file ends with the openssl command that creates it (`&& chmod 600` on Unix). `stpt keygen` comes with RI001.
- AUTH_REQUEST (`auth`): method 1, Account (at most 256 bytes, else LIMIT_EXCEEDED), raw 32-byte key, 64-byte signature over the deterministic CBOR of `["STPT user authentication", exporter, method, Account, key]`. The exporter value is the TLS exporter of the Connection (`quinn::Connection::export_keying_material`, label `EXPORTER-STPT-user-auth`, empty context, 32 bytes); each side computes it itself. Verification: `aws-lc-rs` Ed25519 (RFC 8032).
- Authorized keys (`authorized`): directory `authorized_keys` (default `/etc/stpt/authorized_keys`), one file per Account named like the Account, kept by the administrator. Line: base64 of the key's SubjectPublicKeyInfo (second line of `openssl pkey -pubout`), optional label of 1–64 bytes; `#` comments. Directory and file must be owned by root or by the Server's own user and not writable by group or others, the file must be a regular file; otherwise, or with an invalid line, the file is ignored (fail closed) and the reason logged. An Account name that is not a plain file name (`/`, `\`, `.`, `..`, control characters) is treated as an unknown Account.
- Accounts: `authorized::SystemAccounts` asks the system user database (`getpwnam` through `nix`); tests use their own `Accounts`.
- Decision (`Authorizer::decide`, in `spawn_blocking`, as `getpwnam` and file reading block): signature verification, Account lookup and reading the keys file all run, whichever fails; the decision is made once after them. The exact reason (invalid signature, no such Account, keys file missing, unsafe or invalid, key not listed) goes to the Server log with Account (Debug-escaped) and key fingerprint; the Client gets AUTH_RESULT false.
- Server sequence (`server::authenticate`): AUTH_REQUEST after AUTH_REQUEST until the authentication deadline (60 s); another message type before authentication, or an unoffered method, is PROTOCOL_VIOLATION. A failure is answered no earlier than 300 ms (`Deadlines::failure_delay`) after its AUTH_REQUEST, so the response time does not depend on the reason; the 6th failure closes with AUTH_FAILED instead of a result.
- Authenticated Connection: the Server logs Account, key fingerprint and label and raises the bidirectional stream limit to 1 + 10 (§8.2, §14.5); Channels and requests then follow §8. A further AUTH_REQUEST or CLIENT_HELLO is PROTOCOL_VIOLATION.
- Client (`client::Connection::authenticate`): one key, one AUTH_REQUEST, AUTH_RESULT within 10 s (TIMEOUT). Refused: the Client closes regularly and ends with the key fingerprint and its authorized keys line for the administrator.

# 10	Terminals
PROTOCOL.md §14, §15.1, §15.4, §15.5.

- PTY (`pty`, Unix only): `Pty::open` opens a master/slave pair (`openpty`) with the window size of the Channel (`terminal::Size`: columns, rows, pixel sizes). Termios: system defaults plus `IUTF8` on Linux (and Apple systems); no modes come from the Client. Both descriptors are close-on-exec.
- Master: non-blocking, registered with the Tokio reactor (`AsyncFd`), so reading output and writing input wait without a thread per terminal. `read` returning 0 means end of output: no process holds the slave any more (Linux reports EIO). `resize` sets the size with `TIOCSWINSZ`; the kernel sends SIGWINCH to the foreground process group.
- Processes (`process`, Unix only): `Account::lookup` reads the Account from the user database (`getpwnam`, groups with `getgrouplist`; an empty shell means `/bin/sh`). `spawn` starts the Session's program with `tokio::process` (exit status awaited without a thread):
  - always through the Account's shell, so `nologin` or `git-shell` keep their effect: login shell with argument 0 `-NAME` (as login and sshd), a command line with `-c`, an argument vector with `-c` and each element in single quotes (`'` as `'\''`), so it is neither split nor expanded;
  - on the PTY slave (standard input, output and error, controlling terminal) or with three pipes;
  - in the child before exec (`pre_exec`, system calls only, nothing allocated): every signal back to its default disposition (signals the Server ignores, e.g. INT and QUIT when a shell started it in the background, would stay ignored across exec, and a shell cannot even trap them), `setsid`, so the program has its own session and process group; with a PTY the slave becomes the controlling terminal (`TIOCSCTTY`); then `setgroups`, `setgid`, `setuid` when the Server runs as root; a Server not running as root can start processes only for its own Account; working directory the home, else `/` with a notice on the terminal;
  - environment built from scratch: `HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH` (Debian `login.defs` values, root gets the `sbin` directories), `TERM` (with a PTY only), `STPT_SESSION` and the variables the Client sent that passed the allowlist; nothing of the Server's environment;
  - signals (`signal_group`, §14.9) carry the permissions of the Account, never those of the Server: as root a child is forked that takes the Account's groups, group and user and calls `kill` on the process group, then `_exit`s with the errno (system calls only, no exec, nothing allocated after the fork); the Server waits for it in a blocking task. So a signal never reaches a process the Account could not signal itself, e.g. one started with sudo. A Server not running as root runs as the Account and calls `kill` itself;
  - not done (unlike sshd with PAM): PAM sessions and limits, utmp/wtmp/lastlog, systemd-logind sessions.
- Messages (`terminal`): `Open` is the terminal CHANNEL_OPEN with every parameter of §14.6, encoded by the Client and validated by the Server (a malformed parameter: CHANNEL_REJECTED; environment limits: LIMIT_EXCEEDED; attach parameters on create and creation parameters on attach: CHANNEL_REJECTED). Session ID: 16 bytes from the system random generator, text form 32 hexadecimal digits.
- Server (`session`): a terminal Channel without a Session ID creates a Session: Account looked up again, environment filtered by the default allowlist (`LANG`, `LC_*`), `STPT_SESSION` added; PTY (`pty-params` present) or pipes; a failed start rejects the Channel with CHANNEL_REJECTED and the reason in the log. Then TERMINAL_ATTACHED (Attachment 1, offset 0) and two concurrent loops:
  - input: TERMINAL_DATA to the PTY or to standard input (dropped once the program closed its input); TERMINAL_EOF closes standard input (without a PTY only); TERMINAL_RESIZE sets the PTY size (`TIOCSWINSZ`, so the foreground process group gets SIGWINCH) between the input before and after it; TERMINAL_SIGNAL (ids 1–7; a report-only or unknown id is a violation) goes, with a PTY, to the foreground process group of the PTY (`tcgetpgrp` on the master), without a PTY to the process group of the command, also after TERMINAL_EOF; a target that is gone ignores it; another type, EOF with a PTY, data after EOF, resize without a PTY or an invalid message close the Connection with PROTOCOL_VIOLATION;
  - output: reads of up to 16 KiB as TERMINAL_DATA (PTY, standard output) or TERMINAL_STDERR; the next read waits until the message is written, so QUIC flow control is the backpressure. After the program exited, output is sent until its end, at most for the grace period (1 s, `Deadlines::exit_grace`), so a background process holding the PTY does not hold the exit; then TERMINAL_EXIT (exit code, or signal id with core dump flag) and FIN. Later Client messages are discarded until its FIN.
- Session lifetime until Tier RD: there is no Session store yet, so a Session lives as long as its Channel. An attach is answered with SESSION_NOT_FOUND; the Client's FIN (detach), a reset or a lost Connection end the Session: the PTY master is closed, so the kernel sends SIGHUP as for a closed terminal; without a PTY the pipes are closed. The Server sends FIN without TERMINAL_EXIT after a detach. This deviates from §14.10/§15.5 (a detached Session keeps running) until RD002/RD003.
- Client (`client::Connection::terminal`): `connect` opens a Channel with a PTY running the login shell: TERM from the environment if valid, else `xterm-256color`; size of the local terminal, else 80×24; `--name` passed on. `exec` opens one without a PTY: the arguments joined with spaces into one command line, as ssh does; `--no-shell` sends them as an argument vector. Both pass `LANG` and `LC_*` only. Rejection or reset of the Channel ends the Client with the code name (`terminal: rejected by the Server: SESSION_NOT_FOUND`).
  - Input: a thread reads standard input and hands it to a task that sends TERMINAL_DATA; at the end of input TERMINAL_EOF without a PTY, nothing with one (Ctrl-D is in-band). After TERMINAL_EXIT the task sends FIN.
  - Window size (with a PTY and a terminal on standard output): a task sends TERMINAL_RESIZE when the size of the local window differs from the last one sent, so a burst of changes gives one message with the latest size. Unix: on SIGWINCH (`tokio::signal`). Windows: a poll every 250 ms, as a console read with ReadConsoleW reports no size changes.
  - Output: TERMINAL_DATA to standard output, TERMINAL_STDERR (without a PTY only) to standard error, unbuffered; any other message is a violation.
  - Ctrl+C without a PTY (`exec`): sends TERMINAL_SIGNAL INT (`tokio::signal::ctrl_c`, also a Windows console control event); the third press ends the Client with `interrupted` (255), for a command that ignores INT. With a PTY Ctrl+C is an input byte in raw mode.
  - Exit code: the remote exit code, 255 if it does not fit into 8 bits; after a signal 255 and `stpt: the remote program was killed by signal NAME`, as ssh. A Channel ended without TERMINAL_EXIT: 255, `terminal: ended by the Server`.
- Local terminal (`console`): with a PTY and a terminal on standard input, raw mode while the Channel runs (Unix: `cfmakeraw`; Windows: line input, echo and processed input off, virtual terminal input on), restored when it ends, also on errors. Window size: `TIOCGWINSZ` on standard output; Windows: the visible window of the console screen buffer. Windows output: written with WriteFile in the UTF-8 code page with virtual terminal processing (and DISABLE_NEWLINE_AUTO_RETURN with a PTY), as the standard library's console writer rejects bytes that are not UTF-8; console input: ReadConsoleW converted to UTF-8, as the standard library would end input at Ctrl+Z.

# 11	Dependencies
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
| `tokio` (`io-util`, `macros`, `net`, `process`, `rt-multi-thread`, `signal`, `sync`, `time`) | async runtime | the runtime `quinn` runs on; `net` for `AsyncFd` (PTY master), `process` for Session processes (brings `signal-hook-registry` for SIGCHLD), `io-util` for pipes, `macros` (`select!`) for concurrent input and output, `sync` for the Client input queue, `signal` for SIGWINCH and Ctrl+C on the Client |
| `socket2` | UDP socket options | explicit dual-stack; already used inside `tokio` and `quinn` |
| `nix` (`user`, `term`, `fs`, `ioctl`, `process`, `signal`; Unix only) | Account lookup (`getpwnam_r`, `getgrouplist`), file owner check (`geteuid`), PTY (`openpty`, termios, `fcntl`, `TIOCSWINSZ`), process start (`setsid`, `TIOCSCTTY`, `setgroups`, `setgid`, `setuid`), signals (`fork`, `kill`, `waitpid`, `tcgetpgrp`) | safe wrappers of the Unix calls instead of own `unsafe` FFI |
| `base64` (`std` only) | fingerprints, PEM key file, trust store | the standard Rust base64 crate; strict decoding (no non-canonical trailing bits); without the default `simd-unsafe` feature |
| `windows-sys` (`Win32_System_Console`; Windows only) | Client console: raw mode, window size, UTF-8 output and input | the Windows API bindings `tokio` and `quinn` already use; the console API has no safe wrapper in the standard library. `crossterm` was not taken: it reads console input as events, not as the VT byte stream a remote PTY needs |
