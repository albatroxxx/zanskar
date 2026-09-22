# Roadmap

Approved 2026-09-20. Durations are estimates for a small team; the order matters more than the dates.

| Phase | Duration | Deliverable | Status |
|---|---|---|---|
| 0. Foundations | 2 weeks | Threat model, ADRs, schema, OpenAPI spec, wireframes, repo scaffold with CI security gates, runnable server skeleton | done |
| 1. MVP | 6 weeks | Local auth with Argon2id and TOTP, admin portal (users, groups, targets, credentials, policies), user portal, SSH web terminal over WebSocket, asciicast recording, audit log persistence and verify command, React frontend scaffold | done |
| 2. Desktop and identity | 6 weeks | RDP and VNC through guacd, Windows CLI over WinRM, desktop recording, OIDC and LDAP/AD login, SSH certificate authority mode, file transfer and clipboard policy | done |
| 3. Autoscaling | 6 weeks | AWS ASG enrollment with cross-account IAM role, healthy pool tracking, failover modal, EC2 Instance Connect credential mode, HA gateway deployment, Helm chart, SIEM export | done |
| 4. Enterprise | ongoing | Just-in-time access approvals, live session shadowing and termination, credential rotation, SAML and SCIM, GCP managed instance groups, Azure scale sets, WebAuthn | |

## v1.0 release

Phases 0–3 are done, so the current feature set is packaged as the first tagged
release, v1.0, for a **single-instance** deployment: one gateway, embedded
SQLite, and a guacd sidecar for RDP and VNC. Multi-replica HA and the Helm chart
ship in a later release — the cross-pod control channel (admin terminate and
auditor shadowing across replicas, noted below) is the first Phase 4 item and
gates any HA claim.

Release-prep items tracked before tagging: recording retention (a single disk
fills), a backup command and a rehearsed restore, an install/configuration path,
packaging (deb/rpm, container, checksums, the third-party notices now generated
by `hack/gen-notices.sh`), and a docs-only install validation on a clean VM.

## Phase 0 checklist

- [x] Threat model (`docs/threat-model.md`)
- [x] ADRs 0001 to 0011 (`docs/adr/`)
- [x] Schema and migrations for PostgreSQL and SQLite (`migrations/`)
- [x] OpenAPI 3.1 spec (`docs/api/openapi.yaml`)
- [x] Wireframes (`docs/wireframes.md`)
- [x] Repo scaffold: Makefile, CI with lint, govulncheck, gosec, gitleaks, Trivy, Dependabot
- [x] Runnable skeleton: `serve`, `migrate`, `keygen`, health and readiness, security headers, envelope crypto, audit hash chain
- [ ] Frontend scaffold (needs Node on the dev machine; moved to Phase 1)
- [ ] Sign-off review of threat model and ADRs

## Phase 2 status

Done: RDP and VNC through guacd with certificate pinning (ADR 0012); OIDC login
(discovery, PKCE, sealed state, just-in-time provisioning, group mapping); LDAP/AD
bind-and-search login with the same provisioning; the identity-provider admin API
and UI; SSH certificate authority mode (short-lived per-session certificates, no
stored user key); WinRM PowerShell terminal (line-oriented console) with recording.

Closed 2026-09-21: WinRM TLS is pinned to the listener certificate captured by the
probe (per-protocol fingerprint, plain HTTP refused; ADR 0012 addendum); desktop file
transfer through RDP drive redirection with a browser Files panel, gated by policy and
enforced in the bridge; live session shadowing for admins and auditors (terminal fan-out
with scrollback replay, guacd read-only join for desktops, every watch audited).

Phase 2 is complete.

## Phase 3 status

Done: AWS autoscaling groups as targets (cross-account role with ExternalId, rendered
trust and permissions policies), the sync loop with the ADR 0011 health model, host keys
verified from the serial console with trust-on-first-use fallback, EC2 Instance Connect
credential mode, user Autoscaling tab with instance chooser, failover dialog on instance
loss, admin enrollment and instance views. Also: SIEM export of the audit chain (CEF or
JSON over syslog TCP/TLS, HMAC-signed HTTPS webhook; at-least-once with per-sink
checkpoints), S3-compatible recording storage for multi-gateway deployments, a Helm chart
with hardened pods, guacd isolation and a pre-upgrade migrate hook, and docs/deploy.md
covering topology, HA and its current per-pod limitations.

Phase 3 is complete. Known limitation carried forward: admin terminate and auditor
shadowing act only on sessions hosted by the pod that receives the request; a cross-pod
control channel is the first Phase 4 infrastructure item.

## Phase 1 order of work

1. [x] Users, roles and Argon2id password auth with lockout.
2. [x] Auth sessions (opaque cookie, hashed at rest), CSRF, TOTP enrollment and verification.
3. [x] Audit persistence on top of `internal/audit` and `zanskar audit verify`.
4. [x] Key ring on top of `internal/crypto` with `key_versions` bootstrap.
5. [x] Admin API for users and groups; credentials vault with generated SSH keys.
6. [x] Targets with probe (SSH host key, TLS cert, RDP negotiation, VNC banner) and host key trust workflow.
7. [x] Access policies with tag selectors and time windows; evaluation on every connect.
8. [x] Connect tickets and SSH terminal over WebSocket with asciicast recording, idle and max limits,
   admin terminate, auditor/admin recording stream with audited views.
9. [x] React SPA: login with TOTP verify and enrollment, user portal (targets, terminal, my sessions),
   admin portal, auditor portal; embedded in the binary behind `-tags webui`.
10. [x] Postgres run of the full suite in CI; auth session sweeper. Recording retention moves to Phase 2.
