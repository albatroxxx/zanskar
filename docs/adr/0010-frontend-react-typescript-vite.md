# 0010. Frontend: React, TypeScript, Vite

Date: 2026-09-20

## Status

Accepted

## Context

The frontend must render terminals, remote desktops, and a configuration UI. It must work in
current browsers without plugins. It will be embedded in the Go binary. Two libraries are fixed by
earlier decisions: xterm.js for terminals and guacamole-common-js for desktops (ADR 0002).

Alternatives considered:

- **Two separate applications for admin and user.** Doubles build and dependency surface, and
  the third role from ADR 0006 does not fit a two-portal model.
- **Server-rendered templates with htmx.** Fine for the admin CRUD screens, but terminal and
  desktop rendering are inherently client-side and need a real component model.
- **Svelte or Vue.** Reasonable, but React has the largest pool of contributors and the best
  TypeScript typings for the libraries we depend on.

## Decision

One single-page application written in React with TypeScript, built with Vite, with strict
TypeScript settings and ESLint. The application has three route trees, one per role, mounted
according to the roles returned by the session endpoint. The API refuses anything the UI hides,
so route gating is a usability feature, not a security control.

The admin route tree is built as a separate chunk and can be served from a separate listener or
hostname, configured through `ZANSKAR_ADMIN_LISTEN_ADDR`, so that deployments can restrict admin
access at the network layer. *(Not built: see the amendment below.)*

Terminal sessions use xterm.js over a WebSocket. Desktop sessions use guacamole-common-js over a
WebSocket that the gateway bridges to guacd.

The build output is embedded into the Go binary with `embed`. The Content Security Policy is
`default-src 'self'` with no inline scripts, which rules out any library that injects script tags.

## Consequences

- One dependency tree, one build, one CSP to maintain.
- Node.js is a build-time dependency only. The release binary contains the compiled assets.
- Bundle size matters because xterm.js and guacamole-common-js are large. Code splitting per
  route tree keeps the login page small.
- The UI must never make an authorization decision. Reviewers reject pull requests that hide a
  control without a matching server-side check.

## Amendment, 2026-10-11: no separate admin listener

The separate admin listener was never built. `ZANSKAR_ADMIN_LISTEN_ADDR` was read, validated and
shown on the console's install-time settings, but no second listener was ever bound, so an
operator who set it believed the admin console and API were off the main listener when they were
not. The setting is now refused at start with a message that says so, rather than ignored. The
admin console and API are served on `ZANSKAR_LISTEN_ADDR` together with everything else; the API
refuses what a role may not do, whichever listener a request arrives on.

Restricting admin access at the network layer would need either a second listener with every
route classified as admin or not, or an API split under a path prefix. Neither is planned.

## Amendment, 2026-10-11: what is split

Until now the admin and audit pages were imported statically, so the sign-in page downloaded the
whole console and the recording player in one 683 KB bundle. Each admin and audit page is now a
lazily loaded chunk, fetched the first time it is opened; the entry bundle is about half the size
and the player (with asciinema-player) loads only for playback. The terminal, desktop and shadow
pages were already split.

## Amendment, 2026-10-13: the linter is oxlint

The decision above names ESLint; the console is linted with oxlint instead (`npm run lint`, which
CI runs), configured in `web/.oxlintrc.json` with its React and TypeScript plugins. The type check
is part of `npm run build`, and CI runs both. oxlint reads ESLint-style disable comments, so the
few `react-hooks/exhaustive-deps` directives in the pages are live: each marks an effect keyed on
fewer values on purpose.
