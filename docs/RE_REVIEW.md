# Tier RE scenario review

Date: 2026-11-22. Program: **0.4.1-1**. Protocol: draft-48; normative wire rules are unchanged from draft-47. Scope: RE001–RE004 and all 30 scenarios in the [Tier PE review](https://github.com/berbunda/stpt-protocol/blob/main/docs/PE_REVIEW.md).

The review is complete with the fixes below. No unresolved implementation issue was identified within these scenarios after the fixes and final checks. This is scenario-based implementation validation, not a formal proof or a production security certification. Supported refusals and platform limits remain explicit.

## Findings and fixes

1. **Active FIN and resource lifetime.** A FIN was forwarded as a private worker close message even during an upload, where the worker parsed it as an invalid END and closed the whole Connection. During a backpressured download, waiting for worker output after FIN also bypassed the operation deadline. Reproduced before fixing on Windows; the deadline failure was independently reproduced on Linux. Active FIN now interrupts only the file Channel with NO_ERROR, drops unretained state and leaves other Channels usable. The relay keeps cancellation/deadline monitoring after input completion. Native upload-FIN and download-backpressure regressions pass on both platforms.
2. **Client publication of verified bytes.** After closing verified staging, the Client reopened its source by pathname for hard-link/rename publication. A substituted staging name could publish different bytes. The regression reproduced the wrong bytes on both Windows and Linux before fixing. Unix now creates ordinary download staging inside a private directory and publishes through held source/destination directory descriptors. Windows retains the actual source file handle, denies write/delete sharing, and publishes with native handle-relative link/rename operations. Retained data also uses native non-followed opens and held publication objects. The replacement test now publishes the verified bytes or prevents the substitution; racing final destinations remain protected.
3. **Resume-file privacy.** Unix now checks current ownership and private mode on each opened state file before truncation/writing, not just on its containing directory. Windows checks the actual object's current owner, refuses reparses and protects its DACL before writing, including newly created files; no pathname check is used as a substitute. This prevents relying on inherited grants or granting OWNER RIGHTS to an unrelated owner. Existing checkpoint/locking tests and a new Unix unsafe-state-file regression pass. Native Windows multi-Account logon was not added or claimed.

## Execution results

- Windows: `cargo test` **273 passed**, one manual large-transfer case ignored by default and explicitly run successfully; **274 passing test executions** including that case. Clippy all targets with `-D warnings` passed.
- Ubuntu VM: `cargo test --offline --locked` **308 passed**, seven ignored: six pre-existing non-RE root/long-loss cases and the manual large-transfer case. The large case was explicitly run and passed, giving **309 passing test executions** including it. Clippy all targets with `-D warnings` passed.
- Separate root Linux file suite: **61 passed**, with the already-executed manual large case excluded. This run exercises actual root/nobody authority separation and foreign authenticated Account token refusal; it overlaps the ordinary suite.
- Real large download: **4295032832 bytes** (4 GiB + 64 KiB), complete digest and final receipt/result, bounded hash sink on both platforms. The source is sparse; Linux never needs a 4-GiB destination on its small tmpfs. An actual 4-GiB staged upload was not attempted; upload offset/count boundaries and resource refusals are checked separately.
- Additional final targeted runs cover extended aggregate record/byte quotas, empty directory listings, source growth and native Windows early EOF. Formatting, diff, package/lock version, roadmap-ID preservation and document consistency checks passed.

Commands from the program repository:

```text
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
cargo test --test windows_server review_download_above_four_gib -- --ignored --nocapture
cargo test --test fs review_download_above_four_gib -- --ignored --nocapture
```

The first manual command is Windows-only; the second is Linux-only. Privileged Linux file cases additionally ran under root in the isolated VM workspace.

## Scenario coverage

Shared validation tests execute on both operating systems. Native evidence is listed separately; a code/status model is not presented as an actual disk-full, network-filesystem or cross-Account Windows experiment.

| Scenario from Tier PE review | Windows evidence | Linux evidence |
|---|---|---|
| Capability absent or rejected | Shared negotiation/Server tests; disabled-capability native policy test. | Shared negotiation/Server tests; capability-free terminal compatibility. |
| Channel rejected or opening stalls | Shared opening timeout, cancellation and stream-local rejection tests. | Same shared QUIC tests; native unavailable-worker rejection. |
| Parallel Channels exceed the selected limit | Shared negotiated Channel semaphore/stream limit tests. | Same shared tests; fixed global worker admission inspected. |
| Invalid fields, direction, phase or operation ID | Shared Request/Exchange/Server violation tests and strict metadata parsing. | Same checks; native worker invalid-offset/path-shape/refusal/reuse cases. |
| Empty file | Native CLI empty push/pull, BLAKE3 and SHA-256. | Native CLI empty push/pull, both algorithms. |
| Ordinary file | Native CLI binary roundtrip, management and private publication. | Native CLI binary roundtrip, management and mode checks. |
| File above 4 GiB | Explicit 4 GiB + 64 KiB real Server download to bounded hash sink. | Same real transfer from a sparse source in task tmpfs. |
| Largest data chunk | Shared maximum-frame test: 61440 data bytes, 61469 payload bytes. | Same test, maximum operation ID and valid offset; wire-bound overflow rejected. |
| Empty directory or native dot entries | Native empty-directory CLI assertion; handle enumeration omits dot entries. | Native empty-directory CLI assertion; descriptor enumeration omits dot entries. |
| Listing fails after some batches | Shared fault peer sends entries then failure; native unrepresentable UTF-16 listing fails. | Shared incomplete-listing fault test; native byte-name handling. |
| Account access denied or revoked | Native ACL denial installed after upload acceptance; current-Account authentication boundary. | Root Server / nobody Account native suite; current permissions and publication checks. |
| Disk/quota exhaustion | Native error-code mapping; shared admission/byte quotas and Client failure-abort tests. | Native error mapping plus RLIMIT_FSIZE-injected worker write failure; no publication and cleanup. |
| Source EOF or growth | Native source truncation and append after acceptance; declared length remains authoritative. | Native source EOF, growth, synchronization and reuse test. |
| Wrong count or digest | Shared count/digest precedence; native worker wrong digest and cleanup. | Same shared checks; native worker integrity cases. |
| Empty chunk, gap, overlap or data beyond length | Shared empty/oversize/gap/wrong-ID/excess/overflow DATA validation and phase tests. | Same shared checks; native wrong-offset worker test. |
| Failure within a frame | Shared QUIC framing/Server tests; active FIN now cancels only its Channel. | Same framing checks; native active-FIN/backpressure/upload regressions. |
| Upload interrupted before complete FILE_END | Native interruption/cancellation, forced worker exit and private stage cleanup. | Native worker interruption, authenticated timeout handoff and private cleanup. |
| Complete FILE_END received, result lost | Native consumed-token test plus Client interrupted-result fault test; no automatic fresh retry. | Native consumed-token test plus the same Client result-loss behavior. |
| Download verification/local writes fail | Shared bad-digest/local-setup failure tests: no OK receipt or publication. | Same shared tests; private descriptor-relative Client staging. |
| Verified download, final result lost | Shared verified-END/OK-receipt then lost final result: destination remains unpublished. | Same fault-peer test; no local success or unverified publication. |
| Download resume length/prefix changed | Native prefix mismatch and end-offset tests for both algorithms. | Native changed length/prefix tests for both algorithms. |
| Upload resume local prefix changed | Shared Client compares the prefix digest and cancels without suffix on mismatch. | Same shared Client fault-peer test. |
| Resume at total length | Native both-algorithm full-prefix read tests; ordinary END/receipt/result required. | Native upload/download offset-at-end cases; full logical hash verified. |
| Busy, expired, foreign or consumed token | Native busy/consumed/cancelled/restarted cases; shared expiry/binding/quota tests. | Same plus actual foreign authenticated Account token refusal under root. |
| Destination parent replaced before resume | Native parent rename is denied while pinned; resume rechecks parent ID. | Native changed-parent identity makes resume unavailable. |
| Server restart | Native Server restart invalidates token and removes unpublished stage. | Native restart/deadline/cleanup suite. |
| Symlinks and concurrent path replacement | Native junction entry operations and pinned handles; Client source-name substitution regression. | Native symlink metadata/mutations and Client private-directory substitution regression. |
| Windows reparse point or namespace alias | Native ancestor/final junction refusal; read-only mapping lookup and pure alias validation. | Unsupported Windows path kind; shared namespace grammar tests. Native Windows behavior is Windows-only. |
| Non-UTF-8 POSIX name or cross-platform collision | Shared strict Unicode/byte-name/metadata parsing and explicit local-destination policy. | Actual non-UTF-8 POSIX CLI paths and escaped listing; no derived local names. |
| Slow peer or lengthy prefix verification | Native deadlines/backpressure/FIN; shared bounded prefix verification and queued-transfer tests. | Same plus native deadlines, prefix/parent rechecks and bounded 4-GiB streaming. |

## Evidence and limits

Primary test sources: [file Channel lifecycle](../src/files.rs), [file grammar and phase model](../src/file_protocol.rs), [Client fault peers/publication](../src/file_client.rs), [resume leases and quotas](../src/file_resume.rs), [private checkpoints](../src/file_checkpoint.rs), [Linux CLI/worker/authority suite](../tests/fs.rs), and [Windows native CLI/Server suite](../tests/windows_server.rs). Native storage status tests are in [Unix storage](../src/file_storage_unix.rs) and [Windows storage](../src/file_storage_windows.rs).

- Existing-target `push --replace` still returns UNSUPPORTED on both primary platforms. Create-only publication is enforced by the mutation; `pull --replace` and compatible native `rename --replace` work. This is the explicit safe refusal allowed by the specification, not an unresolved check/rename race.
- Windows serves only its current canonical Account and inherited process token/elevation. Local-volume restrictions and reparse refusals remain. No network/substituted drive mapping was created or changed for this review.
- Disk-full/quota native status mapping, admission quotas and write-error abort/cleanup were verified. Filesystems were not filled to exhaustion; the Linux write fault uses a child-only file-size limit. No filesystem mount, partition, firewall, route or unrelated project was modified. No new crate dependency was added.
- Native tests run locally within Windows and within the Linux VM. This review does not claim a new direct cross-OS network interoperability run, network-filesystem qualification, every filter-driver/filesystem combination, an RSS benchmark, fuzzing, or power-loss durability. The six historical non-RE skips do not stand in for file-profile tests.
- Lost modifying results remain potentially unknown. There is no automatic fresh modifying retry, immutable filesystem snapshot or durable resume receipt. Resume records remain scoped to a running Server instance.
