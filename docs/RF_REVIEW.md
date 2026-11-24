# Tier RF scenario review

2026-11-24 · program 0.4.5-1 · protocol draft-58

The table follows the 24 rows of the Tier PF review in order. Native tests use the Session command, the authenticated Connection and the actual filesystem. QUIC tests control frame order over a loopback Connection. A state test exercises a transition directly when the scheduler cannot reliably force that ordering.

| PF row | Scenario | Implementation evidence |
|---|---|---|
| 1 | Caller claims another Session | Linux rejects a missing inherited endpoint and a caller in another OS session. Windows rejects the correct public ID from outside the Session Job. |
| 2 | No live target or requested ID detached | The selection test covers an empty registry. The Windows Session command refuses a detached ID. The Server does not queue proposals. |
| 3 | Several Attachments with different capabilities | With A mounted and a read-only B attached, the Linux Session command reports ambiguity without an ID, missing capability for B, and a busy slot for A. |
| 4 | B joins or A leaves after selection | The selection test exercises a snapshot. Code review traced A's ID, Connection and detach receiver through dispatch. The QUIC detach test interrupts that exchange without another registry lookup. |
| 5 | Reused numeric ID or reconnect | QUIC refuses another Session using the expected Attachment ID before contacting the broker. Grant tests reject a ticket from a previous Connection scope. |
| 6 | Combinations of capabilities 1, 2 and 3 | HELLO tests enforce the dependency. Native read/create works without a mount. The Linux mount test negotiates both reverse capabilities. |
| 7 | Mount occupies the file slot | The explicit request to A fails while its mount remains readable. B can attach, receive terminal output and detach during this interval. |
| 8 | Wrong phase or direction | QUIC tests send unsolicited START and duplicate APPROVED. Invalid live exchanges are Connection errors. Ordinary refusal and stale target terminate the Channel. |
| 9 | Trusted consent, refusal, expiry | The Linux consent terminal refuses a reused challenge. Both native platforms exercise scripted refusal. QUIC tests cover consent and START timeouts. |
| 10 | Object changes after selection | Grant and publication tests cover a replaced source name, pinned destination parent and no-replace publication. Linux tree tests retain the approved root when its pathname is replaced. |
| 11 | Caller or binding lost before START | QUIC tests cross late approval with caller exit, detach and Session end. Detach during the local two-socket handshake also releases the slot before its opening deadline. |
| 12 | Abort after START, before publication | A QUIC Client receives START and a partial create, then stream reset. The destination remains absent. Stalled input also expires. |
| 13 | Published create or lost result | Native create verifies committed bytes. A QUIC peer that consumes END and drops the Channel yields an unknown outcome. Code review confirms no automatic retry. |
| 14 | Empty create, integrity error, competing destination | Digest tests cover empty content, wrong digest and count. Native no-replace create preserves an existing entry. |
| 15 | END and FIN versus incomplete input | QUIC waits for the create result after END and FIN. Partial input cannot publish. The receiver checks END before treating FIN as completed input. |
| 16 | Shared Session and explicit mount approval | The local prompt identifies the binding, scope, root and other Attachments. The shared Session test approves once, keeps traffic flowing and verifies reads after B leaves. |
| 17 | Setup abandoned or READY crosses detach | Native cancellation during setup yields no mountpoint. A QUIC test sends READY across detach and verifies teardown. Successful setup returns to the shell while the mount remains usable. |
| 18 | Unrelated detach, takeover, Session termination | Native Linux cases keep the mount after B detaches and revoke it when A is displaced or the Session terminates. Termination also ends the process holding the descriptor. |
| 19 | Link, nested mount or moved open file | Linux tests refuse symlink traversal, a crossing into procfs and a read through an existing handle after its file moves outside the root. |
| 20 | Oversized listing, stale handle, mutation | Tree tests check whole-list failure and NOT_FOUND after close. A native mutation through FUSE fails and leaves the Client tree unchanged. |
| 21 | Revocation during asynchronous I/O | A native Session blocks reading its open descriptor with the Client worker suspended. Killing the Server FUSE worker must fail that read and dismiss local consent before the progress timeout. Grant-state tests reject completions for a discarded instance. |
| 22 | Open descriptor, mapping, busy directory, stale callback | Native reads fail after revocation with the descriptor and working directory held. Shared and private mappings cannot populate pages. Fresh mount instances own separate kernel connections, worker pipes and handle tables. |
| 23 | Healthy idle, partial CALL, migration, loss | A loopback mount Channel changes UDP port on the same Connection and exchanges a CALL and REPLY. Idle exceeds the test progress interval. A partial CALL expires. Native silent loss revokes a mounted tree. |
| 24 | Backend unavailable or dies | Installation requires namespace isolation, FUSE initialization and a per-mount abort handle. The native suite exercises Server worker death during a pending read and abrupt Server exit. |

## Corrections

On 0.4.5-0 the new blocked-read test failed. The Server watched the FUSE worker's output while idle but could miss its exit while awaiting a Client reply. The trusted terminal still showed an active grant after the test's ten-second bound. The Server now watches worker exit concurrently with the entire installed mount exchange. The regression waits for a request to reach the suspended Client worker before killing the exact Server helper.

Both dispatch paths now watch detach and Session end while accepting the local caller's two authenticated sockets. Previously an incomplete handshake could retain the sole reverse slot until the opening timeout. Mount setup also checks for an abandoned caller before opening the Channel and preserves protocol errors and timeout codes during pathname handoff.

## Scope

Windows passed 288 tests with one ignored. Debian 12 passed 331 with eight ignored by default. The ignored native FUSE suite was also run explicitly with `STPT_FUSE_TEST_ACCOUNT` and passed all ten lifecycle cases in 125 seconds. Clippy passed on both platforms with warnings denied. An initial parallel Linux run failed the resume-checkpoint lock test outside Tier RF. Subsequent serial and default parallel runs passed. Windows tests used the ordinary user ACL environment after the sandbox's temporary-directory ACLs caused fixture failures.

Linux mount checks require a real FUSE device, mount namespace privileges and fusectl. The suite includes an ordinary Session Account. Windows exercises grants, routing and one-shot operations. UDP migration was tested on loopback at the Channel layer. Asynchronous listing uses the same cancellation path as read. Reuse of an old mount instance is checked at the grant and implementation layers. These last two cases were not separately forced on a physical filesystem.
