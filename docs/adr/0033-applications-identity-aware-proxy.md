# 0033. Applications: web apps reached through an identity-aware proxy

Date: 2026-10-15

## Status

Proposed.

## Context

Hosts, databases and autoscaling groups are reached through Zanskar; internal web
applications are not. Teams still reach those over a VPN, a bastion, or by exposing them.
An "Applications" section would let a policy grant a user an internal web app the way it
grants a host, with the same sign-in, the same approvals and the same audit trail.

Two shapes were weighed in October: an identity-aware proxy, where Zanskar fronts the app
and the user's own browser talks to it, and an isolated browser, where a sandboxed
browser in a container is streamed through guacd like a desktop. The proxy was chosen for
the first version: it is what developers reach for daily, it keeps the gateway host free
of a browser runtime, and the isolated browser remains the right follow-up for
less-trusted audiences, where a recorded session matters more than convenience.

## Decision (proposed)

**An application is a target of a new kind, reached through Zanskar's own reverse proxy
on a per-application subdomain of a domain that is not the console's.**

- **Model**: an application target holds a name, the upstream (`scheme://host:port`, and
  nothing else is ever proxied), an optional CA bundle or certificate pin for the
  upstream's TLS, and tags like any target. Policies grant it under a new protocol,
  `http`; approvals, time windows and idle timeouts apply unchanged. Users see an
  Applications tab in the access portal, administrators an Applications page beside Hosts
  and Databases, and the dashboard's inventory counts them.
- **Addressing**: each application is served at `https://<app>.<apps domain>`. The apps
  domain is a required setting and must differ from the console's host, so an application
  can never read or set the console's cookie. This needs wildcard DNS and a wildcard
  certificate; the TLS manager (ADR 0021) learns to hold a second certificate for it. The
  self-signed console certificate is not acceptable for the apps domain.
- **Session hand-off**: opening an app from the portal redirects to its subdomain with a
  one-time code bound to the user's session and that app; the proxy exchanges it for a
  per-application, host-only cookie. The console cookie never travels to an app host, and
  a `state` parameter plus return-URL validation guard the hand-off.
- **Proxying rules**: the Zanskar cookie and any client-supplied identity headers are
  stripped before the upstream; `Location` headers are rewritten; WebSockets and HTTP/2
  are supported; the upstream is taken only from the target's configuration, so the proxy
  can never be aimed at an address of the user's choosing; upstream TLS is verified
  against the configured bundle or pin, failing closed.
- **Audit**: `app.session.start` and `app.session.end` as audit events, and a per-request
  log — method, path, status, bytes, duration; never bodies, never query strings — kept
  with the gateway's logs, not in the audit chain, so the chain is not flooded (the ADR
  0029 line).
- **Not in the first version**: a signed identity header for upstreams that want to trust
  Zanskar's authentication, a read-only mode, CLI tokens for curl and API clients, and the
  isolated browser.

## Consequences

- Zanskar gains a second listener personality — a reverse proxy — and the network path
  from the gateway to internal applications; policies gate it exactly as they gate hosts.
- Operators must provide an apps domain, its DNS, and a wildcard certificate before the
  first application can be enrolled; the console refuses to enroll one otherwise.
- The threat model gains a section: a hostile or compromised upstream can affect only its
  own subdomain's cookie and never the console; a cross-site scripting flaw in one app
  does not reach another; the gateway cannot be used as an open proxy.
- Documentation: enrolling an application, the domain and certificate prerequisites, and
  what the request log holds.

## Alternatives considered

- **Isolated browser first** — recorded web sessions, but a browser runtime beside the
  gateway (or a worker fleet), egress controls and sandboxing before anyone gets a page;
  the right second step.
- **Path-based routing under the console host** — simpler DNS, but every application
  would share the console's origin and cookie; rejected on that alone.
- **Exposing apps with a plain authenticating proxy and no Zanskar session model** — loses
  approvals, time windows and the audit trail that make Zanskar worth routing through.
