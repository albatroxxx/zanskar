# OpenSSF Best Practices: Silver checklist

Where Zanskar stands against every Silver criterion of the
[OpenSSF Best Practices badge](https://www.bestpractices.dev/en/projects/14924), with the text to
paste into the form. Passing was reached in September 2026. Assessed 2026-09-30 against the
criteria in the badge project's `criteria.yml`; re-check before submitting.

**Summary**: of 55 Silver criteria, 34 are Met, 4 are N/A and 8 more are met once the pull
requests adding their documents or changes merge (Pending). Nine are Unmet: three are SHOULD or
SUGGESTED, but **six are MUSTs**, and Silver needs every MUST:

| Gap | Criterion | What closes it | Owner |
|---|---|---|---|
| One person holds every key | `access_continuity` (MUST), `bus_factor` (SHOULD) | A second maintainer with admin, merge and release rights, with 2FA ([GOVERNANCE.md](../GOVERNANCE.md)) | Maintainer, in progress |
| Coverage is 61.6% | `test_statement_coverage80` (MUST) | Tests to reach 80% statement coverage (`go test -cover ./...`) | Engineering |
| 8 of 22 recent fixes added a test | `regression_tests_added50` (MUST) | Regression tests for fixes from now on (now policy in CONTRIBUTING), and a frontend test runner, since most untested fixes were console fixes | Engineering |
| Database TLS is not verified by default | `crypto_certificate_verification` (MUST) | Default database targets to `verify-full`, with the RDS CA bundle shipped or documented | Product decision |
| The master key lives only in the env file | `crypto_credential_agility` (MUST) | Accept `ZANSKAR_MASTER_KEY_FILE` pointing at a key file of its own | Engineering, small |
| No code of conduct contact | `code_of_conduct` (MUST) | Fill in the contact in [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Maintainer |

Status key: **Met**, **N/A**, **Unmet**, **Pending** (met once the pull request adding the
document or change merges).

## Basics

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| achieve_passing | MUST | Met | Passing badge since September 2026. |
| contribution_requirements | MUST | Met | CONTRIBUTING.md lists the coding style, the tests required with a change, the checks a PR must pass and the design-change process: https://github.com/albatroxxx/zanskar/blob/main/CONTRIBUTING.md |
| dco | SHOULD | Pending | Every commit carries a Signed-off-by line certifying the Developer Certificate of Origin (CONTRIBUTING.md, "Sign your work"). Enforce it with the DCO GitHub app once enabled. |
| governance | MUST | Pending | GOVERNANCE.md defines roles, how decisions are made (PRs, ADRs for design, maintainers settle disputes) and how people join: https://github.com/albatroxxx/zanskar/blob/main/GOVERNANCE.md |
| code_of_conduct | MUST | Unmet | Contributor Covenant 2.1 in CODE_OF_CONDUCT.md; needs its enforcement contact filled in. |
| roles_responsibilities | MUST | Pending | GOVERNANCE.md, "Roles": maintainer, committer and contributor, each with responsibilities, listed by GitHub handle. |
| access_continuity | MUST | Unmet | Needs a second person with admin, merge and release rights (GOVERNANCE.md, "Continuity"). Release signing is keyless (Sigstore via GitHub OIDC), so no private key has to be handed over. |
| bus_factor | SHOULD | Unmet | 1 today; 2 once a second maintainer is active. |
| documentation_roadmap | MUST | Pending | docs/roadmap.md, "The next twelve months": what the project will do (October 2026 to September 2027) and will not do: https://github.com/albatroxxx/zanskar/blob/main/docs/roadmap.md |
| documentation_architecture | MUST | Pending | docs/architecture.md: components, packages, a session end to end, state and deployment shapes, each linked to its ADR: https://github.com/albatroxxx/zanskar/blob/main/docs/architecture.md |
| documentation_security | MUST | Met | docs/threat-model.md (trust boundaries, threats, the controls committed to and residual risks) and SECURITY.md (scope, supported versions): https://github.com/albatroxxx/zanskar/blob/main/docs/threat-model.md |
| documentation_quick_start | MUST | Met | Install and first sign-in: https://albatroxxx.github.io/zanskar/docs/ |
| documentation_current | MUST | Met | Docs change in the same PR as the behaviour; the 1.2.0 test round's findings were all fixed in the docs before and after release (PRs #101, #106 to #109). |
| documentation_achievements | MUST | Met | README shows and links the Best Practices and Scorecard badges. |
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
| coding_standards | MUST | Pending | CONTRIBUTING.md, "Coding style": Effective Go and Go Code Review Comments; TypeScript compiler and oxlint for the console. |
| coding_standards_enforced | MUST | Met | CI fails on unformatted Go (gofmt), golangci-lint (with gosec), go vet, tsc and oxlint. |
| build_standard_variables | MUST | N/A | Pure Go with CGO disabled; no C compiler or linker is invoked, so CC/CFLAGS/LDFLAGS do not apply. |
| build_preserve_debug | SHOULD | Met | `go build` keeps debug information by default; only the release build strips it (`-s -w`), which is the standard for distributed binaries. |
| build_non_recursive | MUST | Met | One `go build` of `./cmd/zanskar` via the Go toolchain's module graph; no recursive make. |
| build_repeatable | MUST | Pending | Two clean builds of the same commit produce identical bytes for every binary, archive, deb and rpm (`-trimpath`, commit-time mtimes; PR #111). |
| installation_common | MUST | Met | deb and rpm packages installed and removed with apt or dnf; a container image for Docker Compose. |
| installation_standard_variables | MUST | Met | Installation is by the system package manager (apt, dnf), which owns install locations; the packages follow the FHS (/usr/bin, /etc/zanskar, /var/lib/zanskar). |
| installation_development_quick | MUST | Met | CONTRIBUTING.md, "Development setup": `make setup`, `make build`, `make all`. |
| external_dependencies | MUST | Met | go.mod / go.sum and web/package-lock.json; THIRD_PARTY_NOTICES.md is regenerated from them and checked in CI. |
| dependency_monitoring | MUST | Met | Dependabot, govulncheck on every change, OSV-Scanner through Scorecard, Trivy filesystem scan. |
| updateable_reused_components | MUST | Met | All reused components are Go modules or npm packages, updated with the standard tools; no vendored copies. |
| interfaces_current | SHOULD | Met | staticcheck (through golangci-lint) flags deprecated APIs; the one deprecated module advisory (x/crypto/openpgp) is for a package Zanskar never imports (osv-scanner.toml). |
| automated_integration_testing | MUST | Met | CI runs `go test -race ./...` on every push and PR, against SQLite and PostgreSQL, plus fuzz targets and a frontend build; results show on each PR. |
| regression_tests_added50 | MUST | Unmet | 8 of 22 bug-fix commits since April 2026 added a test (36%). Now required by CONTRIBUTING.md; most misses were console fixes, which need a frontend test runner. |
| test_statement_coverage80 | MUST | Unmet | 61.6% statement coverage (Go, `go test -cover ./...`, 2026-09-30). |
| test_policy_mandated | MUST | Pending | CONTRIBUTING.md, "Tests are part of the change": new functionality comes with tests in the same PR. |
| tests_documented_added | MUST | Met | As above, in the instructions for change proposals. |
| warnings_strict | MUST | Met | go vet, golangci-lint and gosec fail the build; tsc fails on unused locals and parameters. (Enabling TypeScript `strict` would go further.) |

## Security

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| implement_secure_design | MUST | Met | Least privilege (roles, per-protocol policy, review-only auditors), fail-safe defaults (MFA required, HTTPS only, deny by default), complete mediation (every session through policy and a single-use ticket), no agents on targets. See docs/threat-model.md section 5. |
| crypto_weaknesses | MUST | Met | AES-256-GCM envelope encryption, Argon2id, Ed25519 SSH CA, TLS 1.2+. TOTP uses HMAC-SHA-1 as RFC 6238 specifies, where SHA-1's collision weakness does not apply. |
| crypto_algorithm_agility | SHOULD | Met | Key versions in the key ring allow re-wrapping; SSH and TLS negotiate from the Go standard library's current suites. |
| crypto_credential_agility | MUST | Unmet | TLS keys are separate files and replaceable live; vaulted credentials are sealed in the database. The master key can only come from the environment file today; accept a separate key file. |
| crypto_used_network | SHOULD | Met | HTTPS (TLS 1.2+), SSHv2, SFTP, WinRM over HTTPS, RDP over TLS, LDAPS or StartTLS. Plain HTTP only on loopback behind a TLS proxy, or to redirect to HTTPS. VNC is as secure as the target's VNC server. |
| crypto_tls12 | SHOULD | Met | Every TLS config sets `MinVersion: tls.VersionTLS12`. |
| crypto_certificate_verification | MUST | Unmet | Verified by default for LDAP, OIDC, S3, AWS and syslog; RDP and WinRM certificates are pinned. Database targets default to TLS mode `prefer`, which does not verify; `verify-full` is available but not the default. |
| crypto_verification_private | MUST | Met | Outbound TLS verifies (or checks the pin) during the handshake, before any credential is sent. |
| signed_releases | MUST | Met | SHA256SUMS signed with cosign keyless (Sigstore), images signed, verification commands in every release and on the install page: https://albatroxxx.github.io/zanskar/docs/#install |
| version_tags_signed | SUGGESTED | Unmet | Release tags are annotated but not signed; `git tag -s` with the maintainer's SSH or GPG key would meet it. |
| input_validation | MUST | Met | JSON bodies decoded strictly into typed structs with unknown fields rejected; identifiers, addresses, ports and enums validated against allowlists before use. |
| hardening | SHOULD | Met | Hardened systemd unit, non-root distroless image, CSP and security headers, CSRF tokens, SameSite cookies, read-only guacd container. |
| assurance_case | MUST | Met | docs/threat-model.md: threat model by trust boundary (STRIDE), trust boundaries TB1 to TB7, secure design controls committed to, residual risks and the compliance mapping. |

## Analysis

| Criterion | Level | Status | Justification to paste |
|---|---|---|---|
| static_analysis_common_vulnerabilities | MUST | Met | gosec, CodeQL, govulncheck and Trivy on every change. |
| dynamic_analysis_unsafe | MUST | N/A | Zanskar is Go with CGO disabled; there is no memory-unsafe code. Go fuzz targets run in CI anyway. |
