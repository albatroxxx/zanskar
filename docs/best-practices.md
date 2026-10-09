# OpenSSF Best Practices: Silver checklist

Zanskar holds the **Silver** level of the
[OpenSSF Best Practices badge](https://www.bestpractices.dev/en/projects/14924) since
5 October 2026 (Passing since September 2026). This page keeps the answer given for every Silver
criterion, word for word as submitted, so it can be checked against the repository and kept
current when something changes.

Every MUST is met. The three criteria not met are a SHOULD or SUGGESTED, each on purpose:

| Criterion | Level | Why not |
|---|---|---|
| `dco` | SHOULD | No DCO sign-off, by decision (ADR 0026). |
| `internationalization` | SHOULD | The console is English only for now. |
| `version_tags_signed` | SUGGESTED | Release tags are annotated, not signed; the release artifacts themselves are signed. |

When an answer stops being true, fix the project or update the answer on the badge site and here
in the same change.

Status key: **Met**, **N/A**, **Unmet**.

## Basics

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| achieve_passing | MUST | Met | Passing badge since September 2026. |
| contribution_requirements | MUST | Met | CONTRIBUTING.md lists the coding style, the tests required with a change, the checks a PR must pass and the design-change process: https://github.com/albatroxxx/zanskar/blob/main/CONTRIBUTING.md |
| dco | SHOULD | Unmet | Not adopted, on purpose (ADR 0026): contributions come in under Apache 2.0 section 5, and the CONTRIBUTING intro says so. Revisit if a foundation or a contributing company asks for DCO. |
| governance | MUST | Met | GOVERNANCE.md defines roles, how decisions are made (PRs, ADRs for design, maintainers settle disputes) and how people join: https://github.com/albatroxxx/zanskar/blob/main/GOVERNANCE.md |
| code_of_conduct | MUST | Met | Contributor Covenant 2.1 in CODE_OF_CONDUCT.md; reports go to zanskar@techmanship.in. https://github.com/albatroxxx/zanskar/blob/main/CODE_OF_CONDUCT.md |
| roles_responsibilities | MUST | Met | GOVERNANCE.md, "Roles": maintainer, committer and contributor, each with responsibilities, listed by GitHub handle. https://github.com/albatroxxx/zanskar/blob/main/GOVERNANCE.md#roles |
| access_continuity | MUST | Met | Two maintainers (GOVERNANCE.md, "Roles": @albatroxxx and @Lakshyabh06) can each close issues, merge pull requests, and tag and publish releases. Release signing is keyless (Sigstore via GitHub OIDC), so no private key has to be handed over. Repository settings stay with the owner of the personal account; GOVERNANCE.md, "Continuity", says so: https://github.com/albatroxxx/zanskar/blob/main/GOVERNANCE.md |
| bus_factor | SHOULD | Met | 2: two maintainers with merge and release rights (GOVERNANCE.md). https://github.com/albatroxxx/zanskar/blob/main/GOVERNANCE.md#roles |
| documentation_roadmap | MUST | Met | docs/roadmap.md, "The next twelve months": what the project will do (October 2026 to September 2027) and will not do: https://github.com/albatroxxx/zanskar/blob/main/docs/roadmap.md |
| documentation_architecture | MUST | Met | docs/architecture.md: components, packages, a session end to end, state and deployment shapes, each linked to its ADR: https://github.com/albatroxxx/zanskar/blob/main/docs/architecture.md |
| documentation_security | MUST | Met | docs/threat-model.md (trust boundaries, threats, the controls committed to and residual risks) and SECURITY.md (scope, supported versions): https://github.com/albatroxxx/zanskar/blob/main/docs/threat-model.md |
| documentation_quick_start | MUST | Met | Install and first sign-in: https://albatroxxx.github.io/zanskar/docs/ |
| documentation_current | MUST | Met | Docs change in the same PR as the behaviour; the 1.2.0 test round's findings were all fixed in the docs before and after release (PRs #101, #106 to #109). |
| documentation_achievements | MUST | Met | README shows and links the Best Practices and Scorecard badges. https://github.com/albatroxxx/zanskar#readme |
| accessibility_best_practices | SHOULD | Met | Site: skip link, labelled navigation, alt text on every image (checked by hack/check-site.py), copy buttons with labels, no horizontal scroll at phone width. Console: labelled form fields and keyboard-reachable controls. |
| internationalization | SHOULD | Unmet | The console is English only; strings are not yet extracted for translation. |
| sites_password_security | MUST | N/A | The project's sites (GitHub, GitHub Pages) store no passwords of their own. Zanskar itself stores user passwords as Argon2id hashes with a per-user salt. |
## Change control

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| maintenance_or_update | MUST | Met | Forward-only migrations run at start, so an upgrade is install and restart; the install page and every release's notes document the upgrade path: https://albatroxxx.github.io/zanskar/docs/#update |
## Reporting

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| report_tracker | MUST | Met | GitHub issues with bug and feature forms. |
| vulnerability_report_credit | MUST | N/A | No vulnerability reports resolved in the last 12 months. SECURITY.md commits to crediting reporters in the release notes. |
| vulnerability_response_process | MUST | Met | SECURITY.md: private advisory, acknowledgement within 3 business days, fix within 90 days, credited advisory: https://github.com/albatroxxx/zanskar/blob/main/SECURITY.md |
## Quality

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| coding_standards | MUST | Met | CONTRIBUTING.md, "Coding style": Effective Go and Go Code Review Comments; TypeScript compiler and oxlint for the console. https://github.com/albatroxxx/zanskar/blob/main/CONTRIBUTING.md#coding-style |
| coding_standards_enforced | MUST | Met | CI fails on unformatted Go (gofmt), golangci-lint (with gosec), go vet, tsc and oxlint. |
| build_standard_variables | MUST | N/A | Pure Go with CGO disabled; no C compiler or linker is invoked, so CC/CFLAGS/LDFLAGS do not apply. |
| build_preserve_debug | SHOULD | Met | `go build` keeps debug information by default; only the release build strips it (`-s -w`), which is the standard for distributed binaries. |
| build_non_recursive | MUST | Met | One `go build` of `./cmd/zanskar` via the Go toolchain's module graph; no recursive make. |
| build_repeatable | MUST | Met | A tag rebuilds to the same bytes for every binary, archive, deb and rpm: `-trimpath`, the Go toolchain pinned in go.mod, commit-time file times, fixed file owners and rpm build host (PRs #111, #113). Verified for v1.2.1 by rebuilding the tag on a separate machine and comparing with the release's SHA256SUMS; every release is checked the same way. |
| installation_common | MUST | Met | deb and rpm packages installed and removed with apt or dnf; a container image for Docker Compose. |
| installation_standard_variables | MUST | Met | Installation is by the system package manager (apt, dnf), which owns install locations; the packages follow the FHS (/usr/bin, /etc/zanskar, /var/lib/zanskar). |
| installation_development_quick | MUST | Met | CONTRIBUTING.md, "Development setup": `make setup`, `make build`, `make all`. |
| external_dependencies | MUST | Met | go.mod / go.sum and web/package-lock.json; THIRD_PARTY_NOTICES.md is regenerated from them and checked in CI. https://github.com/albatroxxx/zanskar/blob/main/go.mod and https://github.com/albatroxxx/zanskar/blob/main/web/package-lock.json |
| dependency_monitoring | MUST | Met | Dependabot, govulncheck on every change, OSV-Scanner through Scorecard, Trivy filesystem scan. |
| updateable_reused_components | MUST | Met | All reused components are Go modules or npm packages, updated with the standard tools; no vendored copies. |
| interfaces_current | SHOULD | Met | staticcheck (through golangci-lint) flags deprecated APIs; the one deprecated module advisory (x/crypto/openpgp) is for a package Zanskar never imports (osv-scanner.toml). |
| automated_integration_testing | MUST | Met | CI runs `go test -race ./...` on every push and PR, against SQLite and PostgreSQL, plus fuzz targets, the console tests (Vitest) and a frontend build; results show on each PR. |
| regression_tests_added50 | MUST | Met | 14 of the 27 bug fixes merged from April to early October 2026 (52%) came with a regression test that fails without the fix: 12 of 25 fix pull requests, plus the two fixes in #144. Most misses were early console fixes, made before the console had a test runner (Vitest, in CI since #123). CONTRIBUTING.md now requires a regression test with every fix. |
| test_statement_coverage80 | MUST | Met | 82.1% statement coverage of the gateway's own code (2026-10-09): `go test -coverpkg` across every package except `hack/`, whose test tools are never built into a release, each statement counted once and covered if any test reaches it, with the Docker-backed database-session tests on as in CI. CI publishes the current figure as the README coverage badge. It was 61.6% by per-package counting on 2026-09-30. The 80.2% reported on 2026-10-04 was measured with Go 1.27.1, which over-counted statements in blocks split by a comment; Go 1.27.2 counts them correctly and put the same code at 79.9%, so tests were added until the correct count passed 80%. |
| test_policy_mandated | MUST | Met | CONTRIBUTING.md, "Tests are part of the change": new functionality comes with tests in the same PR. |
| tests_documented_added | MUST | Met | As above, in the instructions for change proposals. |
| warnings_strict | MUST | Met | go vet, golangci-lint and gosec fail the build; tsc fails on unused locals and parameters. (Enabling TypeScript `strict` would go further.) |
## Security

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| implement_secure_design | MUST | Met | Least privilege (roles, per-protocol policy, review-only auditors), fail-safe defaults (MFA required, HTTPS only, deny by default), complete mediation (every session through policy and a single-use ticket), no agents on targets. See docs/threat-model.md section 5. |
| crypto_weaknesses | MUST | Met | AES-256-GCM envelope encryption, Argon2id, Ed25519 SSH CA, TLS 1.2+. TOTP uses HMAC-SHA-1 as RFC 6238 specifies, where SHA-1's collision weakness does not apply. |
| crypto_algorithm_agility | SHOULD | Met | Key versions in the key ring allow re-wrapping; SSH and TLS negotiate from the Go standard library's current suites. |
| crypto_credential_agility | MUST | Met | TLS keys are separate files and replaceable live; vaulted credentials are sealed in the database. Since 1.2.1 the master key can come from its own owner-only file (`ZANSKAR_MASTER_KEY_FILE`, ADR 0025) and is rotated with `zanskar rotate-master`. |
| crypto_used_network | SHOULD | Met | HTTPS (TLS 1.2+), SSHv2, SFTP, WinRM over HTTPS, RDP over TLS, LDAPS or StartTLS. Plain HTTP only on loopback behind a TLS proxy, or to redirect to HTTPS. VNC is as secure as the target's VNC server. |
| crypto_tls12 | SHOULD | Met | Every TLS config sets `MinVersion: tls.VersionTLS12`. |
| crypto_certificate_verification | MUST | Met | Verified by default for LDAP, OIDC, S3, AWS and syslog; RDP and WinRM certificates are pinned. Since 1.2.1 new database targets default to `verify-full` (ADR 0025); weaker modes must be chosen explicitly. |
| crypto_verification_private | MUST | Met | Outbound TLS verifies (or checks the pin) during the handshake, before any credential is sent. |
| signed_releases | MUST | Met | SHA256SUMS signed with cosign keyless (Sigstore), images signed, verification commands in every release and on the install page: https://albatroxxx.github.io/zanskar/docs/#install |
| version_tags_signed | SUGGESTED | Unmet | Release tags are annotated but not signed; `git tag -s` with the maintainer's SSH or GPG key would meet it. |
| input_validation | MUST | Met | JSON bodies decoded strictly into typed structs with unknown fields rejected; identifiers, addresses, ports and enums validated against allowlists before use. |
| hardening | SHOULD | Met | Hardened systemd unit, non-root distroless image, CSP and security headers, CSRF tokens, SameSite cookies, read-only guacd container. |
| assurance_case | MUST | Met | docs/threat-model.md: threat model by trust boundary (STRIDE), trust boundaries TB1 to TB7, secure design controls committed to, residual risks and the compliance mapping. https://github.com/albatroxxx/zanskar/blob/main/docs/threat-model.md |
## Analysis

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| static_analysis_common_vulnerabilities | MUST | Met | gosec, CodeQL, govulncheck and Trivy on every change. |
| dynamic_analysis_unsafe | MUST | N/A | Zanskar is Go with CGO disabled; there is no memory-unsafe code. Go fuzz targets run in CI anyway. |