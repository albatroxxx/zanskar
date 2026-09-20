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
  Postgres tests run when `ZANSKAR_TEST_POSTGRES_DSN` is set (CI does this).

## Before committing

```
gofmt -l . && go vet ./... && go test -race ./... && ~/go/bin/golangci-lint run ./... && gosec -quiet ./... && govulncheck ./...
```

## Smoke test

`scratchpad/smoke.sh` in the session scratchpad stands up a fake SSH server and drives the whole
admin-to-terminal flow against the built binary; recreate it from git history if lost.
