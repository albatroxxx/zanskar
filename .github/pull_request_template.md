<!-- Thanks for contributing to Zanskar. Keep each PR focused on one change. -->

## What does this PR do?

<!-- A short summary of the change and why it's needed. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal change
- [ ] Documentation
- [ ] Build / CI / tooling

## Checklist

- [ ] `make all` passes (lint, race tests, build) and `gofmt -l .` is clean
- [ ] `make sec` (gosec) and `make vuln` (govulncheck) pass
- [ ] New or changed behaviour is covered by tests
- [ ] Schema changes ship a migration in **both** `migrations/postgres` and `migrations/sqlite` (`make migrate-check` passes)
- [ ] Dependency changes: regenerated `THIRD_PARTY_NOTICES.md` (`make notices`) and ran `make tidy`
- [ ] A change to how Zanskar works is captured as an ADR in `docs/adr/`
- [ ] No secrets in code, logs, or audit details

## Security impact

<!-- Zanskar is an access gateway. Note any effect on authentication/authorization, policy
     evaluation, credential handling, session isolation, or the audit log — or write "none". -->
