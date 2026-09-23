# 0016. SSH file transfer over SFTP

Date: 2026-09-23

## Status

Proposed

## Context

Desktop sessions (RDP/VNC) can move files through guacd's drive redirection — the
per-session "Zanskar" drive, exposed to the browser as a files panel (ADR 0002, the guacd
sidecar). SSH sessions have no equivalent: they run through Zanskar's own `sshgw` (a native
Go SSH client bridged to an xterm terminal over a WebSocket), not guacd, so drive
redirection does not apply. The result is an asymmetry — a user on a Linux target has no
first-class way to move a file in or out and falls back to unaudited shell tricks (`curl`,
`wget`, base64 paste), or leaves the tool entirely.

We want the same guarantees SSH access already has: policy-gated, audited, credential reuse,
and no new secret path — extended to file transfer.

## Decision

Add an SFTP channel to `sshgw` and surface it through the existing files-panel UI.

- **Reuse the target's SSH connection.** The gateway opens an SFTP subsystem over the
  *same* authenticated SSH connection it already holds to the target
  (`golang.org/x/crypto/ssh` + `github.com/pkg/sftp` as the client). No second connection,
  no second credential — the SFTP channel rides the session's existing auth.
- **Reuse the desktop files panel.** List / upload / download are exposed to the browser
  with the same component and object-stream plumbing built for the desktop drive, so the UX
  is identical across SSH and desktop. Transfers stream in chunks (large files do not buffer
  whole).
- **Policy-gated by the existing file-transfer permission.** The same permission that gates
  the desktop drive gates SFTP; a policy that disallows files shows no panel and the gateway
  refuses SFTP operations. Default off unless the policy grants it.
- **Audited, not recorded.** Each transfer writes a `file.upload` / `file.download` event
  with the remote path and byte size, never contents. As with the desktop drive, the byte
  stream is a channel separate from the terminal, so it is **not** in the session's asciicast
  recording — the audit events are the record. This gap is stated so it is a known property,
  not a surprise.
- **The account's own filesystem is the boundary.** SFTP operates as the target SSH account;
  Zanskar mediates and audits but never widens what that account can already read or write.
  Path handling is confined server-side to what the account can reach.

## Consequences

- SSH gains the file experience desktop already has, from one shared UI.
- File transfers are visible in the audit log but their contents are not recorded, matching
  desktop drive behaviour; teams that need content capture must rely on the target's own
  logging. Documented in `docs/deploy.md`.
- No new attack surface beyond the SSH account's existing filesystem access — Zanskar adds
  mediation and audit on top of it, and the policy gate can withhold it entirely.
- Windows/WinRM file transfer is a separate story (WinRM is not SSH) and is out of scope
  here; this ADR is SSH/SFTP only.
- ASG SSH targets inherit the feature for free, since they use the same `sshgw` path and the
  group's single credential profile (ADR 0011).
