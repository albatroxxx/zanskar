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
access at the network layer.

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
