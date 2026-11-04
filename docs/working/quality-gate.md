# The quality gate

## Every change ships with its tests

A feature is not done without unit tests for what it does and what it refuses. A fix is not done
without a regression test that fails on the old code. Copy changes update the tests that assert the
copy. The console's tests live beside the component (`X.test.tsx`), the gateway's beside the package
(`x_test.go`); an engine-sensitive query (`ON CONFLICT`, `LOWER()`, `LIKE … ESCAPE`, JSON columns,
timestamps) is tested on both engines through `storetest.ForEachBackend`.

## The break-it pass

Before a change is called done, the person who built it tries to break it: the wrong input, the
second request, the lost connection, the stale row, the other engine, the narrow window, the user
who is not an administrator. Findings are fixed in the same batch, each with its regression test,
and named in the commit. A change that was only shown to work has not been reviewed.

## The local gate, before every push

```
gofmt -l . && go vet ./... && go test -race ./... && ~/go/bin/golangci-lint run ./... && gosec -quiet ./... && govulncheck ./... && (cd web && npm test)
```

- `golangci-lint` must be a build that can read the current Go toolchain's export data; CI runs
  the latest and so should you (an older lint silently skipped packages once).
- The Postgres tests run when `ZANSKAR_TEST_POSTGRES_DSN` points at a database (a
  `postgres:16-alpine` container on port 5433; see CLAUDE.md for the command); CI always runs
  them.
- `npm test` is vitest with coverage; `npx oxlint` and `npx tsc -b` are part of the build.
  Fast-refresh and set-state-in-effect warnings that predate a change are known; new ones are not
  allowed.
- The e2e specs (`hack/e2e.sh`, Playwright) run against a built binary with a toy SSH server;
  run them when a flow changes, always before a release.
- `hack/smoke.sh` drives the admin-to-terminal flow against the binary; `hack/keycloak/run.sh`
  and `hack/authentik/run.sh` check single sign-on against two real vendors in Docker.
- Touching `site/`: `python3 -I hack/check-site.py` (links, anchors, metadata, JSON-LD, sitemap,
  image alternatives).

## Guard tests that keep the copies honest

Some facts are written in more than one place, and a test holds them together:

- every audit action has a console label (`TestActionsMatchConsoleLabels`, against
  `web/src/pages/audit/eventText.ts`);
- every timestamp column is rewritten for the engine (`TestEveryTimestampColumnIsRewritten` in
  `internal/store`);
- the two migration sets have the same file names (`make migrate-check`, also in CI);
- the OpenAPI document parses and names every route (`cmd/zanskar/openapi_test.go`);
- the third-party notices match the dependency graph (regenerated with every dependency bump).

When adding a copy of a table (a protocol list, a kind list), add it to a guard test or do not add
the copy.

## Seeing it work

Tests are necessary, not sufficient: a UI change is looked at. The project keeps a **local mock**
recipe — build the console and the gateway from the branch, run the binary on a loopback port with
an in-memory or scratch database, seed hosts, databases, applications, users and policies through
the API, sign in as a seeded administrator and user — and screenshots from it are what the owner
reviews. An application session needs guacd and the browser and relay images; the relay's own log is
the proof of what it allowed and refused. A live gateway is walked after an upgrade with a fresh
eye: every page, every kind, the console errors and the network calls (a walk found ten things in
1.18.0 that no test did).

## What "done" means

Built, tested, broken and fixed, seen working, committed locally with its message, and the
release note's line drafted. Then it waits for the batch.
