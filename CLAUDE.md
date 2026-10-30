# Zanskar — working notes for Claude Code

Agentless VM access gateway in Go. Module path `github.com/albatroxxx/zanskar`. Read
`docs/roadmap.md` for where we are and `docs/adr/` before changing any design decision.

## Conventions

- Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`.
- One package per domain under `internal/` (`user`, `group`, `credential`, `target`, `policy`,
  `session`, `connect`, ...). Each exposes a repo over `*store.DB` and, where it has HTTP routes,
  a handler with `Register(mux *http.ServeMux)` wired in `cmd/zanskar/main.go` via `server.Deps`.
- Handlers use `internal/httpx` (WriteJSON, WriteError, DecodeJSON, Paging, Page) and guard routes
  with `auth.RequireAuth` / `auth.RequireRole`. Every mutation records an `audit.Event` through
  `audit.Actor{...}.Event(...)`; details never contain secrets.
- SQL: write `?` placeholders and call `db.Rebind`. Timestamps go in as `store.TimeArg` and come out
  through `store.NullTime`. IDs come from `store.NewID`. JSON columns are TEXT on SQLite, JSONB on
  Postgres; keep both migration sets identical in file names (CI checks) and portable in syntax.
- **SQLite runs on a single connection.** Never issue a second query while a `*sql.Rows` cursor is
  open; drain and close it first, or the process deadlocks.
- Secrets are sealed with `keyring.Ring.Encrypt(keyring.AAD(table, id), ...)` and the key version
  is stored beside the ciphertext.
- Tests use SQLite in-memory (`file::memory:?_pragma=foreign_keys(1)`) plus `store.Migrate`.
  Postgres tests run when `ZANSKAR_TEST_POSTGRES_DSN` is set (CI does this). A repository test
  that touches an engine-sensitive statement (`ON CONFLICT`, `LOWER()`, `LIKE ... ESCAPE`, JSON
  columns, timestamp comparisons) runs through `storetest.ForEachBackend`, which gives each test
  a migrated schema of its own on Postgres. Locally: `docker run -d --name zanskar-pg-test
  -e POSTGRES_USER=zanskar -e POSTGRES_PASSWORD=zanskar -e POSTGRES_DB=zanskar_test -p 5433:5432
  postgres:16-alpine` and `ZANSKAR_TEST_POSTGRES_DSN='postgres://zanskar:zanskar@127.0.0.1:5433/zanskar_test?sslmode=disable'`.
- Tests hash passwords with reduced argon2id parameters (`internal/user/password.go`, gated on
  `testing.Testing()`); nothing a test does can change what a built binary hashes with.

## Before committing

```
gofmt -l . && go vet ./... && go test -race ./... && ~/go/bin/golangci-lint run ./... && gosec -quiet ./... && govulncheck ./... && (cd web && npm test)
```

## Smoke test

`hack/smoke.sh` stands up `hack/fakessh` (a toy SSH server, password test/pw) and drives the whole
admin-to-terminal flow against `bin/zanskar` with `hack/wsclient`. Build the helpers first:
`go build -o bin/fakessh ./hack/fakessh && go build -o bin/wsclient ./hack/wsclient`.
For a local demo target, run `./bin/fakessh` and enroll `<your LAN IP>:2222` as a Linux target.

`hack/keycloak/run.sh` checks single sign-on against a real Keycloak in Docker (ADR 0035): user
sync, sign-in with Keycloak's OTP and nothing from Zanskar, and sign-out ending Keycloak's session.
`hack/authentik/run.sh` checks the same against Authentik, a second vendor: SCIM 2.0 push, an
email-form username, sign-out, and `prompt_login` with a provider that ignores it. Keep features
vendor-neutral (OIDC, SCIM, LDAP); a vendor adapter only beside the standard path.
