# Contributing to Zanskar

Thanks for your interest in Zanskar. This guide covers how to report issues and how to work on the
code. Zanskar is licensed under [Apache 2.0](LICENSE); by contributing you agree your contributions
are licensed under the same terms.

## Reporting bugs and requesting features

Open an issue and pick a form:

- **Bug report** — something isn't working as it should.
- **Feature request** — an idea or improvement.

Please **do not** open a public issue for a security vulnerability. Follow [SECURITY.md](SECURITY.md)
to report it privately.

## Development setup

You need **Go 1.27+** and **Node 22+**.

```sh
make setup            # once per clone: activates the git hooks in .githooks/ and lists any missing tools
cp .env.example .env
export ZANSKAR_MASTER_KEY=$(go run ./cmd/zanskar keygen)
go run ./cmd/zanskar migrate
go run ./cmd/zanskar admin create --username admin --name "Your Name"
make build            # web UI + single binary with it embedded
./bin/zanskar serve   # SQLite, plain HTTP on 127.0.0.1:8443
```

For frontend work, run `make web-dev` (Vite on :5173, proxying to the API) alongside `make run`.

`hack/smoke.sh` stands up a toy SSH server and drives the whole admin-to-terminal flow against a
built binary — a good end-to-end check. Build the helpers first:
`go build -o bin/fakessh ./hack/fakessh && go build -o bin/wsclient ./hack/wsclient`.

## Before you open a pull request

The repo ships git hooks in `.githooks/`, activated by `make setup`. **pre-commit** refuses a
commit that contains a secret (gitleaks with `.gitleaks.toml`, which knows Zanskar's own
`ZANSKAR_MASTER_KEY` / `ZANSKAR_ADMIN_PASSWORD` shapes), unformatted Go, or a file that looks
like an env file or private key. **pre-push** runs govulncheck and gosec. CI runs the same
scanners and blocks the merge regardless, but a secret that reaches a public branch is already
exposed, so the hooks are the layer that actually protects you. `git commit --no-verify` and
`ZANSKAR_SKIP_PREPUSH=1` exist for a genuine false positive; fix `.gitleaks.toml` afterwards.

Run the same checks CI runs, and make sure they pass:

```sh
make all           # lint + test + build
make sec           # gosec
make vuln          # govulncheck
gofmt -l .         # should print nothing
```

Individual targets: `make test` (race + coverage), `make lint` (golangci-lint), `make vet`,
`make sec` (gosec), `make vuln` (govulncheck). golangci-lint, gosec and govulncheck must be
installed locally; CI runs all of them plus a secret scan and a container scan.

If you touched:

- **dependencies** (Go or npm) — run `make notices` to regenerate `THIRD_PARTY_NOTICES.md`; CI fails
  if it is stale, and run `make tidy` for `go.mod`.
- **the database schema** — add a migration to **both** `migrations/postgres` and `migrations/sqlite`
  with identical file names and portable SQL; `make migrate-check` verifies the two sets match.

## Conventions

- Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`.
- One package per domain under `internal/` (`user`, `group`, `target`, `policy`, `session`,
  `connect`, ...). Each exposes a repository over the store and, where it has HTTP routes, a handler
  registered in `cmd/zanskar/main.go`.
- HTTP handlers use the shared `internal/httpx` helpers and guard routes with the `auth` middleware.
  Every mutation records an audit event; audit details never contain secrets.
- SQL uses `?` placeholders (rebound per driver) and must run on both PostgreSQL and SQLite. SQLite
  runs on a single connection — never issue a second query while a result-set cursor is open.
- Secrets are sealed through the keyring (envelope encryption); never log or store them in the clear.
- Tests use an in-memory SQLite database; the Postgres path is exercised in CI.

## Design changes

Anything that changes how Zanskar works — a new protocol, a new security model, a storage decision —
is captured as an **architecture decision record** in [docs/adr/](docs/adr/). If your change is
substantial, propose an ADR (copy the format of an existing one) so the reasoning is on the record
before the code lands.

## Pull requests

- Branch from `main`; keep each PR focused on one change.
- Write a clear description of what changed and why. Reference the issue it closes.
- CI must be green (build, tests, lint, security scans) before a PR is merged.
