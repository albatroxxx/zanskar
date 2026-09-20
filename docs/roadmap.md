# Roadmap

Approved 2026-09-20. Durations are estimates for a small team; the order matters more than the dates.

| Phase | Duration | Deliverable | Status |
|---|---|---|---|
| 0. Foundations | 2 weeks | Threat model, ADRs, schema, OpenAPI spec, wireframes, repo scaffold with CI security gates, runnable server skeleton | in progress |
| 1. MVP | 6 weeks | Local auth with Argon2id and TOTP, admin portal (users, groups, targets, credentials, policies), user portal, SSH web terminal over WebSocket, asciicast recording, audit log persistence and verify command, React frontend scaffold | next |
| 2. Desktop and identity | 6 weeks | RDP and VNC through guacd, Windows CLI over WinRM, desktop recording, OIDC and LDAP/AD login, SSH certificate authority mode, file transfer and clipboard policy | |
| 3. Autoscaling | 6 weeks | AWS ASG enrollment with cross-account IAM role, healthy pool tracking, failover modal, EC2 Instance Connect credential mode, HA gateway deployment, Helm chart, SIEM export | |
| 4. Enterprise | ongoing | Just-in-time access approvals, live session shadowing and termination, credential rotation, SAML and SCIM, GCP managed instance groups, Azure scale sets, WebAuthn | |

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

## Phase 1 order of work

1. Users, roles and Argon2id password auth with lockout.
2. Auth sessions (opaque cookie, hashed at rest), CSRF, TOTP enrollment and verification.
3. Audit persistence on top of `internal/audit` and `zanskar audit verify`.
4. Credentials vault on top of `internal/crypto` with `key_versions` bootstrap.
5. Targets with probe and host key trust workflow.
6. Groups and access policies; policy evaluation service.
7. Connect tickets and SSH terminal over WebSocket, with asciicast recording.
8. React SPA: login, user portal, admin portal, auditor portal.
