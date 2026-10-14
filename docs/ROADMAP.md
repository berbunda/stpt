This document answers for questions:"In which order is the STPT program implemented?"
Realisation track (R) of the roadmap (RULES.md §1.4). The protocol track (P) is in `stpt-protocol/docs/ROADMAP.md`.
`← Pxxxx` names the protocol items an item depends on; it starts only once they are at least draft.
IDs A001–D008 were renamed to RA001–RD008 on 2026-10-11 (prefix scheme change); the bare IDs are retired.

# 1	Tier RA — Foundation / Local Prototype
- [x] RA001  Project bootstrap: repositories, Rust project, licenses, docs, build check ✅ 2026-10-10
- [x] RA002  CLI skeleton ✅ 2026-10-13
- [x] RA003  unified client/server binary ✅ 2026-10-14
- [x] RA004  configuration subsystem ✅ 2026-10-14
- [x] RA005  logging/error subsystem ✅ 2026-10-14
- [ ] RA006  local client ↔ server communication prototype

# 2	Tier RB — Transport
- [ ] RB001  QUIC transport ← PB001
- [ ] RB002  TLS 1.3 ← PB001
- [ ] RB003  server identity ← PB005
- [ ] RB004  client ↔ server handshake ← PB006
- [ ] RB005  STPT protocol negotiation ← PB007
- [ ] RB006  authentication ← PB008
- [ ] RB007  control stream ← PB003, PB004

# 3	Tier RC — Terminal MVP
- [ ] RC001  Linux PTY
- [ ] RC002  shell spawning
- [ ] RC003  terminal I/O ← PC001, PC003
- [ ] RC004  terminal resize ← PC004
- [ ] RC005  signals / Ctrl+C ← PC005
- [ ] RC006  interactive applications ← PC002
- [ ] RC007  graceful disconnect ← PC006

# 4	Tier RD — Session Model
- [ ] RD001  Session ID ← PD001
- [ ] RD002  detached sessions ← PD002
- [ ] RD003  session persistence after disconnect ← PD002
- [ ] RD004  session list ← PD004
- [ ] RD005  session attach ← PD003
- [ ] RD006  session terminate ← PD002
- [ ] RD007  automatic reattach ← PD005
- [ ] RD008  QUIC connection migration ← PD005
- [ ] RD009  detach timeout in Client config; help, man and README explain that closing the window detaches ← PD002 ➕ 2026-10-13
- [ ] RD010  detach from another window: all Attachments or one by ID ← PD003 ➕ 2026-10-13

# 5	Tier RE — File Transfer
- [ ] RE001  file transfer Channel ← PE001 ➕ 2026-10-13
- [ ] RE002  `stpt fs`: transfer and file management ← PE002, PE003 ➕ 2026-10-13
- [ ] RE003  resume of transfers ← PE004 ➕ 2026-10-13
- [ ] RE004  metadata and Windows paths ← PE005 ➕ 2026-10-13

# 6	Tier RF — Client-side File Access
- [ ] RF001  permission grants on the Client ← PF001 ➕ 2026-10-13
- [ ] RF002  `stpt` command inside a Session ← PF002 ➕ 2026-10-13
- [ ] RF003  Server-opened Channel, confirmation dialog ← PF003 ➕ 2026-10-13
- [ ] RF004  directory mount on Linux (FUSE) ← PF004 ➕ 2026-10-13

# 7	Tier RG — Port Forwarding
- [ ] RG001  local forwarding ← PG001 ➕ 2026-10-13
- [ ] RG002  remote forwarding ← PG002 ➕ 2026-10-13
- [ ] RG003  dynamic forwarding (SOCKS) ← PG003 ➕ 2026-10-13
- [ ] RG004  Server forwarding policy ← PG004 ➕ 2026-10-13

# 8	Tier RH — Audit
- [ ] RH001  Server audit log ← PH001 ➕ 2026-10-13
- [ ] RH002  terminal I/O recording ← PH002 ➕ 2026-10-13
- [ ] RH003  `stpt history` ← PH003 ➕ 2026-10-13

# 9	Tier RI — Authentication / Identity
- [ ] RI001  `stpt keygen`, user key storage ← PB008 ➕ 2026-10-13
- [ ] RI002  authorized keys and labels ← PI001 ➕ 2026-10-13
- [ ] RI003  per-key restrictions ← PI002 ➕ 2026-10-13
- [ ] RI004  Server key rotation ← PI003 ➕ 2026-10-13
- [ ] RI005  hardware keys ← PI004 ➕ 2026-10-13
- [ ] RI006  post-quantum keys ← PI005 ➕ 2026-10-13
- [ ] RI007  certificates and CA ← PI006 ➕ 2026-10-13

# 10	Tier RJ — Hardening
- [ ] RJ001  Server privilege separation ← PJ001 ➕ 2026-10-13
- [ ] RJ002  fuzzing of CBOR and protocol parsing ➕ 2026-10-13
- [ ] RJ003  Client escape-sequence protection ← PJ003 ➕ 2026-10-13
- [ ] RJ004  sandboxing (seccomp, landlock) ➕ 2026-10-13
- [ ] RJ005  keystroke timing obfuscation ← PJ005 ➕ 2026-10-13
- [ ] RJ006  dependency audit ➕ 2026-10-13

# 11	Tier RK — Packaging / Deployment
- [ ] RK001  Debian package, systemd unit ➕ 2026-10-13
- [ ] RK002  Windows build (Client) ➕ 2026-10-13
- [ ] RK003  man pages, shell completion ➕ 2026-10-13
- [ ] RK004  reproducible builds, release signing ➕ 2026-10-13
- [ ] RK005  test vector verification ← PK002 ➕ 2026-10-13
- [ ] RK006  Windows Server mode (ConPTY) ➕ 2026-10-13

# 12	Backlog — on request
Items taken up only when users ask for them.
- [ ] RG005  UDP forwarding ← PG005 ➕ 2026-10-13
