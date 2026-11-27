# STPT 0.5.0-1 release notes

This release includes local, remote and dynamic TCP forwarding for Windows
and Linux x86-64, with fixes for cancellation, quota accounting and timeouts.
The [TCP forwarding scenario review](RG_REVIEW.md) records the tested cases.

- [x] TA001  dependency audit ✅ 2026-11-27
- [x] TA002  basic fuzzing of parsers ✅ 2026-11-27
- [x] TA003  preparing a Windows/Linux build with checksums ✅ 2026-11-27
- [x] TA004  updating the documentation ✅ 2026-11-27

## TA001 dependency audit

On 2026-11-27, `cargo-audit 0.23.0` checked all 140 packages in the STPT
`0.5.0-1` lockfile (program commit `51e310e`) against 1,568 RustSec
advisories. The scan used no OS, architecture or severity filter and no
advisory exclusions. It reported zero vulnerabilities and zero warnings.
[RustSec database revision](https://github.com/RustSec/advisory-db/tree/c9f6c91a44dbad9d71742329e9df061279f9c4be)

| Release target | Packages in the normal and build dependency tree, including STPT | Findings |
| --- | ---: | --- |
| Windows x86-64 MSVC | 82, including `windows-sys 0.61.2` | None |
| Linux x86-64 GNU | 107, including `fuser 0.19.0` and `nix 0.31.4` / `0.32.0` | None |

Both target trees were resolved from the audited lockfile. No dependency
update is required by this audit.

To repeat the check, use the lockfile at the program commit above and a local
checkout of the linked RustSec revision. Run from the program repository:

```text
cargo audit --file Cargo.lock --db <advisory-db-path> --no-fetch --json
cargo tree --locked --target x86_64-pc-windows-msvc -e normal,build
cargo tree --locked --target x86_64-unknown-linux-gnu -e normal,build
```

## TA002 parser fuzzing

On 2026-11-27, the Windows x86-64 MSVC debug test build of STPT
`0.5.0-1` completed 100,000 generated cases with zero panics or failed
assertions. The [test harness](../src/wire/parser_fuzz.rs) uses a fixed
seed (`0x5354505400000002`). It alternates arbitrary byte strings of 0–256
bytes, byte mutations of encoded messages, and field mutations that preserve
the message envelope.

The ten starting messages exercise Client and Server HELLO, authentication
request and result, Session list request ID, terminal resize/data/exit, a
file request, and opening a remote forwarding rule. Each starting message
must pass its body parser before mutation.

| Parser stage | Observed result |
| --- | --- |
| CBOR | 36,430 inputs decoded. Each re-encoded byte for byte. |
| Message envelope | 35,755 inputs decoded. Acceptance agreed with the expected envelope shape for every case. Each accepted envelope re-encoded byte for byte. |
| Message body | The selected parsers accepted 4,257 and rejected 31,280. The other 218 decoded envelopes had message types outside the selected set. |

This was an in-process payload test with deterministic mutations. Coverage-guided
instrumentation, sanitizers, QUIC stream framing, multi-message state transitions
and a native Linux run were outside the campaign.

To reproduce from the program repository:

```text
cargo test --locked --bin stpt -- parser_fuzz::release_parser_fuzz --exact --ignored --nocapture
```

## TA003 release binaries

On 2026-11-27, STPT `0.5.0-1` was built natively on Windows and Linux
with Rust 1.100.0 and `cargo build --release --locked --bin stpt`. Linux
used commit `51e310e03fa76cbf2f22fd090daa69272904ec0c`. The Windows
checkout was at the same commit with the TA002 test harness added under
`cfg(test)`. Both executables printed `stpt 0.5.0-1` on their build hosts.

The artifacts and `SHA256SUMS` are in the local program repository under
`target/dist/stpt-0.5.0-1/`. The SHA-256 of each final copy was verified
against the digest computed on its build host.

| Target | Artifact | Verified SHA-256 |
| --- | --- | --- |
| `x86_64-pc-windows-msvc` (PE AMD64) | `windows-x86_64/stpt.exe` | `d85695cafec8f2b8e61a43e58021e6c751cc61dcbd79204d53d8f0256b0dbd2f` |
| `x86_64-unknown-linux-gnu` (dynamically linked ELF x86-64) | `linux-x86_64/stpt` | `8956249a019626c402bd2975282057a9b6aa535f5965d0435e1272c7a079a081` |

To verify a copy of the distribution on Linux, run `sha256sum -c SHA256SUMS`
from the directory containing the manifest and both platform directories.

## TA004 release documentation

On 2026-11-27, the [README verification instructions](../README.md#stpt-050-1-release-binaries)
were updated with the distribution layout, a single-binary SHA-256 check for
each platform, and the expected version output. The source build instructions
now use the release lockfile. Both per-platform checks and the full manifest
check passed against the TA003 artifacts.
