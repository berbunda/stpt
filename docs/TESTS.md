# STPT Test Plans

## Session continuity after a Client IP address change

Status: planned (2026-11-08). Related items: RD007, RD008; protocol §15.12.

Goal: verify that changing the Client's IP address preserves the running Session, either through QUIC connection migration or automatic reattach after Connection loss.

### Setup

- Test Windows 11 and Linux Clients against a Linux Server whose address remains reachable from both Client networks.
- Use a trusted Server key and an authorized user key. Keep the Server running throughout each scenario.
- Leave `detach_timeout` unset and allow enough `reattach_timeout` for the test.
- Start `stpt -v connect ACCOUNT@HOST --name ip-change`. Record the Session ID (`STPT_SESSION`) and shell PID (`echo $$`). Run a numbered output loop; repeat with a full-screen application such as `htop`.
- Record Client and Server logs, old and new Client addresses as seen by the Server, outage duration and time until output resumes.

### Scenarios

- [ ] **Migration with active output:** switch Wi-Fi to a mobile hotspot (or otherwise replace the Client IP) with an outage shorter than the 60 s idle timeout. Verify output and input continue on the same Connection, with the same Session ID and shell PID. Check the migration log and updated Client address.
- [ ] **Migration while idle:** change the IP while the terminal is idle, then type a command. Verify the Connection migrates and input/output resume; repeat by switching back to the original network.
- [ ] **Reattach after a long outage:** disconnect the Client for clearly longer than 60 s, then restore connectivity with a different IP. Verify `connection lost` followed by `attached again`, full authentication on a new Connection, and the same Session ID and shell PID. Verify no new Session is created.
- [ ] **Input during reattach:** after `connection lost` appears, type a harmless distinctive command before connectivity returns. Verify it is discarded and does not execute after reattach; newly typed commands must work.
- [ ] **Output and screen recovery:** verify numbered output resumes without gaps or duplicates when it fits the replay buffer. Repeat with more than 256 KiB of output during the outage and verify the lost-byte notice. With `htop`, verify redraw, keyboard input and terminal resize after recovery.

### Evidence and existing checks

For each scenario, record the application version, Client/Server OS, network transition, Session ID and PID before/after, observed Connection migration or reattach, recovery time and pass/fail result. These planned checks have not been run as part of creating this file.

- `tests/network_change.sh`: existing Linux network-namespace migration checks (`sudo bash tests/network_change.sh target/debug/stpt`); requires root. Complements the real Windows Wi-Fi/hotspot test.
- Ignored loss tests in `tests/terminal.rs`: existing automatic-reattach checks (`cargo test --test terminal -- --ignored` on Linux); take more than a minute per scenario. They complement testing an actual IP change.
