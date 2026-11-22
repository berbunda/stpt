# stpt
Secure terminal access over QUIC: a single program acting as client and server, with Sessions that survive the loss of a connection.

Status: early development. Terminals and Sessions work, and `connect` attaches again by itself after a lost connection.

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
- `stpt server` runs the Server, every other command the Client. Server mode is available on Linux and Windows 11 (ConPTY). Windows currently serves only its own process Account/token; file operations use the same Account/token on local volume drives (G3 resolved).
- `stpt help COMMAND` shows the options of a command.
- Messages go to standard error. `-v` shows more (`-vv`, `-vvv` even more), `-q` errors only. The Server logs to standard error, which systemd keeps in the journal.

# Terminal
`stpt connect alice@host` starts the login shell of the Account `alice` on the Server in a new Session, with a terminal. `stpt exec alice@host COMMAND...` runs a command without a terminal: its output and error output arrive separately, and `stpt` exits with the exit code of the command.

- As with ssh, the arguments of `exec` form one command line for the shell of the Account: `stpt exec alice@host 'ls *.log'` expands `*` on the Server. `--no-shell` passes each argument unchanged.
- On Unix Servers, Ctrl+C during `exec` interrupts the remote command; a command that ignores it keeps running, and pressing Ctrl+C three times ends `stpt` itself. In `connect` Ctrl+C goes to the remote shell, including Windows ConPTY. A Windows command without ConPTY has no isolated console INT equivalent and ignores that signal; use `terminate` to end its Session.
- Exit code 255: an STPT or connection error, the remote program was killed by a signal (`stpt` names it), or `stpt` was interrupted.
- Stopping the Server (`systemctl stop`, TERM, or Ctrl+C in the foreground) ends all Sessions; the Clients report `closed by the peer: SERVER_SHUTDOWN`.
- The Server starts the shell as the Account, so it must run as root (or as that Account). The environment is that of a login: `PATH` and the locale come from `/etc/environment` and `/etc/default/locale` (or `/etc/locale.conf`) on the Server. Of the Client's environment only `LANG` and `LC_*` reach the shell and replace the Server's locale; `STPT_SESSION` holds the Session ID.
- If the Client's locale is not installed on the Server, programs fall back to ASCII and warn (`locale: Cannot set LC_CTYPE`), as with ssh: install it on the Server (`sudo locale-gen ru_RU.UTF-8` on Debian) or unset `LANG` on the Client.

# Sessions
A Session keeps running when its Client goes: after `Enter ~ .` (detach, as the escape of ssh), a closed window or a lost connection. Attach to it again from any computer with a key of the same Account.

**Closing the window does not end the Session, it only detaches.** Its programs keep running and detached Sessions accumulate on the Server until you end them with `exit` or `stpt terminate`, or set `detach_timeout` (see Configuration).

```
stpt sessions alice@host                       # list the Sessions of the Account
stpt connect alice@host --name work            # a new Session named work
stpt connect alice@host --attach work          # attach to it again
stpt detach alice@host work --all              # detach all Attachments (from another window)
stpt terminate alice@host work                 # end it: HUP, KILL after 5 s (--force: at once)
```
- `SESSION` is the Session ID, its name, or a unique beginning of the ID as `stpt sessions` shows it.
- Several Clients may be attached to one Session at once; all see the output, all may type. `--read-only` only watches; `--takeover` detaches the others first. The size of the window that typed last applies.
- Attaching shows the last output of the Session first (up to 16 KiB), so a full-screen program redraws.
- A Session whose program has exited stays until a Client has seen its exit status (at most 24 hours), so `stpt connect --attach` still shows how it ended.
- In `connect`, `~.` is recognized only at the start of a line: right after Enter, or first thing after attaching. Mouse movement and other reports of the terminal in between do not matter; arrow keys, function keys and Esc do. Type `~~` for a `~` at the start of a line. With a non-English keyboard layout, switch to English for `~`.
- Stopping the Server ends all Sessions.

A change of network (Wi-Fi to mobile, a new address) is not even a lost connection: within about a second the Client moves its connection to the new address, and `connect` and `exec` go on without a message. An outage shorter than a minute just pauses them.

A lost connection in `connect` is repaired automatically: the Client notices it after 60 s of silence, says `connection lost`, logs in again with your key and continues where the output stopped.
- What you type until `attached again` appears is dropped, so a command typed blindly never runs later. `Enter ~ .` gives up; `stpt connect --attach` still continues the Session.
- If the Session produced more than the Server keeps (256 KiB) meanwhile, the Client says how many bytes were lost, and a full-screen program redraws.
- Over a full-screen program the messages appear on the last row; after attaching, the program is made to redraw by a brief size change. With `--read-only` the size cannot change: the screen stays as it is until the program redraws by itself.
- The Client stops trying after an hour (`reattach_timeout`, see Configuration), and at once if the Server key has changed, your key is refused or the Session is gone.
- `exec` does not reconnect: it reports the lost connection and exits with 255. Input is not numbered like output, so reconnecting could silently lose part of what a pipe sends to the command.

# Files
`stpt fs` transfers regular files and manages files on Linux and Windows Servers under the Account's filesystem permissions. It needs no terminal or Session. Linux Server paths are absolute POSIX paths; Windows Server paths are absolute local-volume drive paths. Local paths use the Client's native syntax. Windows serves the same exact current Account/token as its terminal service (see Windows Server below); G3 is resolved in 0.4.1-0.

```
stpt fs push alice@host ./local.bin /home/alice/remote.bin
stpt fs pull alice@host /home/alice/remote.bin ./copy.bin
stpt fs stat alice@host /home/alice/remote.bin
stpt fs list alice@host /home/alice
stpt fs mkdir alice@host /home/alice/new-directory
stpt fs rename alice@host /home/alice/old-name /home/alice/new-name
stpt fs remove alice@host /home/alice/empty-directory
```

- Every operation accepts `--fingerprint` and `-i` as the terminal commands do. `stpt fs help COMMAND` describes its arguments. Success exits with 0; file or Connection errors with 255.
- Push and pull transfer one regular file. No recursive copying, wildcard expansion, implicit parent creation or automatic destination-name selection is performed. Uploads use private staging and are published atomically only after verification. An interrupted or failed upload does not expose a partial destination.
- BLAKE3 verifies transfers by default. `--hash sha256` on push or pull explicitly requests SHA-256; the Server confirms that exact algorithm. Data stays inside QUIC/TLS in both cases. Files use bounded blocks, including files larger than 4 GiB; both roles default to an 8 GiB per-file limit.
- Existing destinations are protected by default, including a destination created concurrently with the transfer. Pull `--replace` explicitly permits local replacement; rename `--replace` permits an atomic native replacement. **Push cannot replace an existing destination yet:** even with `--replace` it returns UNSUPPORTED. This preserves the protocol's regular-file-only replacement requirement without a check/rename race. There is no delete-and-retry fallback.
- `list` prints kind, logical size (or `-`) and a byte-escaped entry name, separated by tabs; `stat` prints kind and size. A failed listing may already have printed incomplete batches. Neither transfers nor listings are filesystem snapshots. Add `--metadata` to stat/list to append mtime, POSIX rwx mode and Windows read-only columns. Timestamps, permissions and source ACLs are informational and are not copied.
- Final symlinks are inspected, removed or renamed as entries. This implementation refuses downloads through final symlinks; Linux directory listing may follow one. Windows refuses traversal through every reparse point, including junctions and a final directory link. Devices, FIFOs and sockets are not transferred. The service is not confined to the home directory: normal Account permissions apply.
- Download publication keeps the verified staging object pinned: Unix uses a private directory and descriptor-relative publication; Windows uses a protected file and native file/directory handles. Swapping a temporary name cannot substitute unverified bytes.
- Ctrl+C cancels the operation. A Connection loss or missing final result is an error; a modifying operation may already have committed. STPT does not automatically retry it. Explicit resume and path/metadata rules are described below. File Channels and terminal Sessions can run concurrently on either primary platform.

## Paths and metadata
The remote path chooses its own kind independently of the Client OS. `/home/alice/a` uses POSIX byte components; a Windows drive path such as `'C:\Data\a'` or `'c:/Data/a'` uses Unicode text components and an uppercase drive letter. Quote paths as required by your shell. POSIX paths supplied on Unix preserve non-UTF-8 bytes and ordinary backslashes; Windows input that cannot be represented as Unicode scalar text is refused. Names are never case-folded or Unicode-normalized. An unsupported path kind returns UNSUPPORTED; Linux Servers do not reinterpret Windows paths as POSIX names.

Windows paths reject UNC, device/extended namespaces, drive-relative paths, ADS, empty components, `.`/`..`, control/reserved characters, trailing ASCII dots/spaces and reserved device names (including extensions and COM/LPT superscript variants). A drive root may be used for stat/list only. POSIX roots have the same operation restriction. Native filesystem name/length/permission checks still apply on the Server. Windows resolves actual local drive roots to volume GUIDs, refuses network and substituted drive aliases, and opens one component at a time relative to pinned directory handles. It inspects final links for stat/remove/rename without following them. Uploads use protected owner/SYSTEM/Administrators ACLs, delete-on-close staging and atomic no-replace hard-link publication. Filesystems must support the required native ACL, handle identity and hard-link operations; unsupported operations are refused. Pinned directories cannot be moved or deleted until the operation or retained upload ends. Ordinary Windows sharing conflicts can cause ACCESS_DENIED.

```
stpt fs stat alice@host /home/alice/a --metadata
stpt fs list alice@host /home/alice --metadata
```

The usual columns remain unchanged; `--metadata` appends `mtime`, `mode`, `readonly`, separated by tabs. Missing/inapplicable values are `-`. Mtime is UTC epoch `[seconds,nanoseconds]` with nine fractional digits: `[-1,500000000]` denotes half a second before 1970. POSIX mode is three octal rwx digits, with no set-ID/sticky bits; Windows read-only is `true`/`false`. Linux stat and directory listings inspect final links as entries and report their own metadata, not the target's. Stat sizes may exceed the configured transfer limit. Unknown entry kinds display as `other` without inferred attributes.

Listing names are validated for their remote path kind and escaped for terminal display. POSIX bytes keep their byte-escaped form; Windows Unicode text preserves visible characters while escaping controls and direction-formatting characters. No local path is constructed from a remote listing name: downloads always use the explicit local destination, avoiding implicit name conversion, collisions and link traversal. Metadata never grants authority or changes destination ACLs, ownership, attributes or timestamps. New uploads retain their private creation policy; rename uses native metadata semantics.

## Resume
Add `--resume-state DIRECTORY` to push or pull to opt in. After a lost Connection or file timeout, rerun the **same command** with the same directory to request resume explicitly:

```
stpt fs push alice@host ./local.bin /home/alice/remote.bin --resume-state ./upload-state
stpt fs pull alice@host /home/alice/remote.bin ./copy.bin --resume-state ./download-state
```

The directory belongs to one transfer: it binds the verified Server Identity, Account, remote path, local path, algorithm and replacement policy. Use a dedicated private directory; STPT requires mode 0700 and the current owner on Unix, and restricts its Windows DACL to the owner and SYSTEM. Existing state files must also belong to the current user and remain private. Windows creates state directories/files atomically with a private descriptor and explicit current owner, checks the opened object before writing, and refuses unsafe existing state. Concurrent use is locked. Download state must be on a filesystem that can publish to the chosen local destination using the requested native operation; choosing a directory beside that destination is recommended. Both endpoints reread and hash the prefix, then verify the whole file including that prefix. A changed download length/prefix is refused; a changed upload prefix cancels the attempt. A changed suffix is not an immutable historical snapshot.

There is no automatic retry, restart from zero or hash downgrade. `RESUME_BUSY` means the earlier upload still owns the token; retry the same command after it ends. `RESUME_UNAVAILABLE` can mean expired, evicted, mismatched, consumed or restarted Server state; it does not prove whether an upload was published. In particular, loss of the final result after FILE_END leaves an unknown outcome. Inspect the destination before deciding on a separate fresh transfer. A refused resume keeps its Client record; use another directory for a deliberate fresh attempt. A zero-byte download checkpoint cannot resume and likewise needs an explicit fresh attempt.

Server upload state is private to the running Server and expires one hour after interruption. Fixed limits reserve the full declared lengths: 4 uploads / 8 GiB per Account, 16 uploads / 16 GiB total, within the 32-worker limit. Upload retention is admitted on the first request of a new file Channel. Only detected Connection loss or a no-progress timeout before complete FILE_END qualifies; Ctrl+C, explicit cancellation, errors, complete FILE_END and graceful Server shutdown discard upload state. Retained workers keep Account-owned staging and the original directory identity; current authentication, credentials, permissions and policy are rechecked. Server restart invalidates tokens. The Server holds no download resume state.

Successful completion and explicit cancellation remove the Client record and partial data; an empty directory and its lock file remain for safe concurrent locking. Keep tokens and partial files private. To abandon saved Client state, remove the dedicated directory when no command uses it; interrupted Server uploads expire independently. Without `--resume-state`, transfers retain their previous cleanup behavior.

# Private key, public key, fingerprint
Three different texts appear around keys. Do not mix them up.

<details>
<summary>What each one looks like and where it is</summary>

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
</details>

# Windows Server
Windows 11 runs terminal Sessions through ConPTY and commands through built-in Windows PowerShell (`-NoProfile`). The Account is the exact canonical name returned by `[Environment]::UserName` on the Server. It must match the Account in `ACCOUNT@HOST` and its authorized-keys filename. Domain aliases and other Accounts are refused; no password logon, S4U, Account switching or impersonation is performed. Processes use the Server's current token, including its elevation state. Run it with the token you intend to grant the authorized keys.

Default Server files are under `%PROGRAMDATA%\stpt`. For a foreground Server without administrator setup, choose a dedicated directory under your own `%LOCALAPPDATA%`, create its `authorized_keys` subdirectory and pass an explicit configuration file. Protect the directory, configuration and authorized keys from writes by other ordinary Accounts. For example, in PowerShell, for a new directory you own:

```powershell
$stptServerDir = Join-Path $env:LOCALAPPDATA 'stpt-server'
$stptAccount = [Environment]::UserName
New-Item -ItemType Directory -Force $stptServerDir | Out-Null
icacls $stptServerDir /inheritance:r /grant:r "${stptAccount}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
New-Item -ItemType Directory -Force (Join-Path $stptServerDir 'authorized_keys') | Out-Null
```

Put the authorized public-key line in `authorized_keys\ACCOUNT`. Create `server.toml` with your actual absolute paths (TOML single quotes preserve backslashes):

```toml
identity_key = 'C:\Users\Alice\AppData\Local\stpt-server\server_key'
authorized_keys = 'C:\Users\Alice\AppData\Local\stpt-server\authorized_keys'
listen = '127.0.0.1:843'
```

Run `stpt server --config PATH --fingerprint`, verify the fingerprint on the Client, then start `stpt server --config PATH`. Select a reachable listen address explicitly for remote access. Private keys are created with an owner/SYSTEM/Administrators DACL; unsafe key/configuration ACLs and final reparse points are refused. Keep installation/configuration ancestor directories under trusted control as well.

Windows supports `connect`, `exec`, Sessions, detach/reattach, resize and termination. `--no-shell` transports arguments through a private single-binary helper so empty arguments, quotes and metacharacters reach a native executable unchanged. Batch files require an explicit shell command. ConPTY dimensions are limited by Win32 signed coordinates (32767 per dimension); oversized openings are refused. TERM/KILL/HUP map to owned Job termination; unsupported POSIX signals are ignored. Closing the Server, even forcibly, closes its kill-on-close Jobs and ends Session descendants. Windows service installation is still RK007. `stpt fs` is available for this same Account/token on local volume drives; file limits, explicit resume and private upload publication apply as described above. G3 is resolved. The [Tier RE scenario review](docs/RE_REVIEW.md) is complete in 0.4.1-2, including native Windows/Linux tests and real downloads above 4 GiB.

# Server key
The Server proves its identity with a key, as an ssh host key. It creates the key at its first start, in `/etc/stpt/server_key` on Linux or `%PROGRAMDATA%\stpt\server_key` on Windows (setting `identity_key`), readable by its owner only; the Server refuses a key file that others can read.

`stpt server --fingerprint` prints the fingerprint of the key (and creates the key if there is none), for example `SHA256:Ab2wRB0yBlg7vMlVGGyOb2TjVLdVNyYGUNUmY/dw6hQ`. Give it to the users of the Server by a channel you trust.

<details>
<summary>How the Client checks the Server key</summary>

The Client remembers the key of every Server it trusts, in `known_servers` next to its configuration file:
- First connection: the Client shows the fingerprint and asks; type `yes` only if it equals, in full, the fingerprint you got from the administrator. Or pass that fingerprint with `--fingerprint`: then the Client checks it and does not ask. Without a terminal and without `--fingerprint` the Client refuses to connect.
- Later connections: the key must be the remembered one.
- Changed key: the Client refuses to connect and shows both fingerprints. Someone may be intercepting the connection, or the Server got a new key. Only after the administrator confirms the new key, remove the old one with `stpt trust remove HOST[:PORT]` and connect again.

`stpt trust list` shows the remembered Servers and their fingerprints.
</details>

# User key
You log in with a key, as with ssh keys; there are no passwords. Create the key once on the Client with OpenSSL (create the `stpt` directory first if it does not exist yet):

| Client | Command |
|---|---|
| Linux | `openssl genpkey -algorithm ed25519 -out ~/.config/stpt/id_ed25519 && chmod 600 ~/.config/stpt/id_ed25519` |
| Windows | `openssl genpkey -algorithm ed25519 -out %APPDATA%\stpt\id_ed25519` |

`-i PATH` uses another key file. On Linux the key file must be readable by you only. Windows key files must have a trusted owner and a DACL that prevents ordinary other users from reading or changing them; SYSTEM and Administrators are trusted.

<details>
<summary>Allowing a key to log in to an Account</summary>

The administrator of the Server decides which keys may log in to which Account (an operating system account on the Server). Show your public key with `openssl pkey -in ~/.config/stpt/id_ed25519 -pubout` and give its second line (it starts with `MCowBQYDK2VwAyEA`) to the administrator; the Client also prints that line when the Server refuses the key.

On the Server, the keys of the Account `alice` are in `/etc/stpt/authorized_keys/alice`, one per line, optionally followed by a label:
```
MCowBQYDK2VwAyEAk9YxouLpNL+A/ZjwtDwMeKhGGVbPOnq2vhNQXSwd7Q4= alice-laptop
```
Only root may change these files: the directory and the files must belong to root and must not be writable by group or others (`chmod 755` for the directory, `644` for the files), otherwise the Server ignores them. A refused login tells the Client nothing about the reason; the Server log has it.
</details>

# Configuration
TOML files, optional; `--config PATH` uses another file.

| Role | Default file |
|---|---|
| Server, Linux | `/etc/stpt/server.toml` |
| Server, Windows | `%PROGRAMDATA%\stpt\server.toml` |
| Client, Linux | `~/.config/stpt/config.toml` (`$XDG_CONFIG_HOME/stpt/config.toml` if set) |
| Client, Windows | `%APPDATA%\stpt\config.toml` |

Command line options override the file. Unknown keys and invalid values are errors.

<details>
<summary>Server settings</summary>

```toml
listen = "[::]:843"   # address and UDP port; IPv6 addresses in brackets; [::] also accepts IPv4
log_level = "info"    # error, warn, info, debug or trace; -v and -q override it
identity_key = "/etc/stpt/server_key"   # Server key file, created if missing
authorized_keys = "/etc/stpt/authorized_keys"   # directory of authorized user keys, one file per Account
max_file_channels = 8   # per Connection; 0 disables selection
max_file_size = 8589934592   # bytes per transfer, default 8 GiB
file_timeout = 60   # seconds without file-operation progress (1–86400)
exit_grace = 1   # seconds output is still sent after the program of a Session exited (0–60)
```
</details>

<details>
<summary>Client settings</summary>

```toml
detach_timeout = 3600   # seconds a new Session may stay without an Attachment, then it is terminated
max_file_size = 8589934592   # bytes per transfer, default 8 GiB
file_timeout = 60   # seconds without file-operation progress (1–86400)
reattach_timeout = 3600   # seconds `connect` keeps trying to attach again after a lost connection; 0: not at all
```
- Without `detach_timeout` a detached Session stays until it is terminated or the Server stops.
- The time of `detach_timeout` starts when the last Attachment ends, including after a lost connection, and restarts with every detach. With `0` the Session ends as soon as it has no Attachment.
- It is fixed when the Session is created (`connect` without `--attach`, `exec`): changing the file does not affect existing Sessions. The Server may apply a shorter time.
</details>

# Build
Requires Rust 1.100 or newer, installed with rustup (distribution packages are usually older), and a C compiler: `build-essential` on Debian, the Visual Studio Build Tools (C++) on Windows. The cryptographic library (AWS-LC) is compiled from C.

```
cargo build --release
```

The program is `target/release/stpt` (`stpt.exe` on Windows).

Roadmap of the program: `docs/ROADMAP.md`.
