This document answers for questions:"In which order is the STPT program implemented?"
Realisation track (R) of the roadmap (RULES.md §1.4). The protocol track (P) is in `stpt-protocol/docs/ROADMAP.md`.
`← Pxxxx` names the protocol items an item depends on; it starts only once they are at least draft.
IDs A001–D008 were renamed to RA001–RD008 on 2026-10-11 (prefix scheme change); the bare IDs are retired.

# 1	Tier RA — Foundation / Local Prototype
- [x] RA001  Project bootstrap: repositories, Rust project, licenses, docs, build check ✅ 2026-10-10
- [ ] RA002  CLI skeleton
- [ ] RA003  unified client/server binary
- [ ] RA004  configuration subsystem
- [ ] RA005  logging/error subsystem
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

# 5	Tier RE — File Transfer

# 6	Tier RF — Client-side File Access

# 7	Tier RG — Port Forwarding

# 8	Tier RH — Audit

# 9	Tier RI — Authentication / Identity

# 10	Tier RJ — Hardening

# 11	Tier RK — Packaging / Deployment
