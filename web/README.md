# Zanskar web console

The React + TypeScript console that the gateway serves from a single binary. It is built with
Vite and embedded into the Go binary at `make build` (`-tags webui`); nothing here is deployed on
its own.

## Working on it

```sh
make web-dev      # Vite on http://127.0.0.1:5173, proxying /api and /ws to the gateway
make run          # the gateway on 127.0.0.1:8443, in another terminal
make web          # production build into web/dist, what `make build` embeds
npm run lint      # oxlint + type checks, the same as CI
```

Sign in at the Vite URL; the API calls go to the running gateway. Types in `src/api/types.ts`
mirror `docs/api/openapi.yaml` and the Go JSON tags; keep them in step when a route changes.

## Layout

- `src/pages/admin` — the administrator console: Hosts, Databases, Autoscaling groups,
  Credentials (with the SSH certificate-authority setup panel), Policies, Users & groups,
  Sessions, Recordings, Audit, Retention, Logs, Settings (runtime settings, TLS certificate,
  recording storage).
- `src/pages/user` — what a user sees: Targets, My access (just-in-time requests), My
  sessions, the terminal and desktop pages.
- `src/pages/audit` — the audit log viewer shared by admins and auditors.
- `src/components/ui.tsx` — the small component set (Modal, Confirm, Field, Badge, Alert…).
- `src/styles` — tokens and base styles; warm neutrals with one ultramarine accent, light and
  dark.

## Conventions

- Every mutation goes through an explicit Save or a confirm; drawers discard on close.
- Nothing in the console ever shows a secret: public keys, fingerprints and "secret stored"
  badges only.
- Keep the layout usable at phone width; the pages are plain CSS, no component library.
