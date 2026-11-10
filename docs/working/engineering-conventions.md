# Engineering conventions

CLAUDE.md at the root is the short form the tools read; this is the same set with the reasons.

## Go

- Every file starts with `// SPDX-License-Identifier: Apache-2.0`.
- One package per domain under `internal/` (`user`, `group`, `credential`, `target`, `policy`,
  `session`, `connect`, `notify`, …). A domain exposes a repository over `*store.DB` and, when
  it has routes, a handler with `Register(mux *http.ServeMux)`, wired in `cmd/zanskar/main.go`
  through `server.Deps`. Gateways (the things that carry a session: `sshgw`, `winrmgw`, `dbgw`,
  `browsergw`, `apprelay`) live under `internal/gateway/`.
- Handlers use `internal/httpx` (`WriteJSON`, `WriteError`, `DecodeJSON`, `Paging`, `Page`) and
  are guarded by `auth.RequireAuth` / `auth.RequireRole`. A refusal has a code and a sentence a
  person can act on; the request id is in every error.
- Comments say why, in sentences, often with the date and the finding that led to the code
  ("live, 2026-11-03: …"). A reader of the code should not need the commit log.
- Dependencies are bumped in batches (Dependabot groups), the third-party notices regenerated
  with them (`hack/gen-notices.sh`), and a bump that closes a CVE is named in the release note.

## SQL and storage

- `?` placeholders, then `db.Rebind` — the same statement runs on SQLite and Postgres.
- Timestamps go in as `store.TimeArg` and come out through `store.NullTime`; ids come from
  `store.NewID`. JSON columns are TEXT on SQLite and JSONB on Postgres.
- **SQLite runs on a single connection.** Never issue a second query while a `*sql.Rows` cursor
  is open: drain and close it first, or the process deadlocks.
- Migrations are a numbered pair, `migrations/sqlite/NNNN_name.sql` and
  `migrations/postgres/NNNN_name.sql`, same name, portable syntax; CI refuses a mismatch. A
  migration that forgets data says why in its comment. The next number is one above the highest
  in both sets (there are gaps in the history; leave them).
- A table that holds a sealed value is in the key-rotation list; a column that holds a time is in
  the rewrite guard test.

## Lifecycles

- A record whose life is a state machine (a session, a request, a token, a rotation) declares it
  **once**, beside its types, with `internal/states` ([ADR 0047](../adr/0047-lifecycles-declared-once.md)):
  the states in order, the moves with what makes each (the audit action, else the verb), and one
  derivation `StateOf(row, now)`, pure over the struct, never a query. `status` is what was set;
  `state` is what holds now. The handlers put `StateOf`'s answer in the record's `state` field; the
  console reads it (`web/src/api/states.ts`, `StateBadge`) and derives nothing from raw fields.
- A move from the wrong state is refused **in the statement** (the predicate names the columns the
  state is read from, compare-and-swap), and the refusal names both states: `states.Error`, or the
  package's own sentence. Error codes do not change for it; messages do.
- A new lifecycle, state or move goes in the declaration, the catalog
  (`internal/states/catalog`), the label table, the OpenAPI enum and `docs/lifecycles.md`
  (`go run ./hack/gen-lifecycles > docs/lifecycles.md`); the guard tests in
  `cmd/zanskar/lifecycles_test.go` name whichever copy was forgotten.

## Tests

- Unit tests run on SQLite in memory (`file::memory:?_pragma=foreign_keys(1)` plus
  `store.Migrate`); anything engine-sensitive goes through `storetest.ForEachBackend`, which gives
  each test its own migrated schema on Postgres when `ZANSKAR_TEST_POSTGRES_DSN` is set.
- Tests hash passwords with reduced argon2id parameters, gated on `testing.Testing()`: nothing a
  test does can change what a built binary hashes with.
- A test is named for the rule it holds and carries the date and finding it came from in a
  comment; the table of cases is explicit, so a reader sees what is covered.
- Fakes stand in for systemd, the container runtime and the network (`fakeHost`, `fakessh`, the
  rig's fake API servers); nothing in a unit test needs Docker. Docker-backed tests are gated by
  `ZANSKAR_TEST_DOCKER=1`.

## The console (web/)

- React with Vite; pages under `web/src/pages/{admin,user,audit}`, shared components under
  `web/src/components`, the API client in `web/src/api/client.ts` (`api.get`, `api.cached` for
  what changes slowly, `api.post`…), types in `web/src/api/types.ts` mirroring the OpenAPI schemas.
- Every audit action has a sentence in `web/src/pages/audit/eventText.ts`; the Go test fails when
  one is missing.
- Styling is tokens in `web/src/styles/base.css`; no inline colours; the layout gives way to one
  column below 900 px.
- Tests are vitest with Testing Library, one file per component; `web/src/test/setup.ts` forgets
  the client's shared reads between cases. Playwright specs under `web/e2e/` drive a built binary.
- Lint is oxlint; the type check is `tsc -b`; both run in the build.

## Secrets in the repository

None. The pre-commit hook runs gitleaks with the project's rules; the mock's generated passwords
live in `bin/` (ignored). A fixture secret is obviously fake (`p4ss`, `mock-…`).

## Naming the time

Dates in comments, ADRs and notes are ISO (`2026-11-03`); times in the console follow the
operator's time zone setting; the publish date in `latest.json` is the real one.
