# 0034. Applications: web apps opened in an isolated browser

Date: 2026-10-27

## Status

Accepted. Supersedes [ADR 0033](0033-applications-identity-aware-proxy.md).

## Context

ADR 0033 reached internal web applications through an identity-aware reverse proxy: each
application at its own name under an apps domain, with a wildcard certificate, and the
console's public address set by name. The first operator to enrol one (2026-10-27, an nginx
at a private address on a LAN without DNS) did not get through: the design asks for a DNS
name, a certificate that no public authority issues for such a name, and trust for that
certificate on every client, before a single page is served. The readiness checklist and
the no-DNS recipe of 1.6.0 explain the prerequisites; they do not remove them. The
operator's verdict was that the model is a headache and hard to understand.

ADR 0033 named the alternative it set aside: a sandboxed browser in a container, streamed
through guacd like a desktop. Everything that model needs already exists here: the desktop
bridge, recording, clipboard policy, shadowing, end reasons, and the database path's
per-session containers on a private network (ADR 0017).

## Decision

**An application is opened in a browser that runs beside the gateway, in a container made
for that session, and streamed to the user as pixels. The proxy, the apps domain, the
wildcard certificate and the hand-off are removed.**

- **Model.** An application target keeps its name, its upstream (`scheme://host[:port]`),
  an optional CA bundle for an https upstream, and tags. Policies grant it under the `http`
  protocol as before. No credential is attached: the application's own sign-in, if it has
  one, is the user's. The per-application label and the apps domain setting go.
- **Session.** Opening an application issues a ticket like a desktop and connects on
  `/ws/desktop`. The gateway creates, per session, an internal network with no route out,
  a browser container on that network alone, and a relay container on that network and on
  the runtime's default bridge. The relay is the gateway's own image running `zanskar
  apprelay`: it forwards the upstream's port, and only that port, to the upstream's
  address, and forwards the browser's VNC port to the bridge side for guacd. The browser's
  resolver maps the upstream's host name to the relay and everything else to nothing, so
  the browser can reach the one application and nothing else, whatever a page asks for.
  guacd connects to the relay with a password made for the session; the bridge, the
  recording, the clipboard policy, the idle and maximum limits, terminate, shadowing and
  the end reasons are the desktop's, unchanged.
- **The browser.** A published image, `ghcr.io/albatroxxx/zanskar-browser`, built from
  Debian's Chromium and TigerVNC, chosen by the `apps.browser_image` runtime setting under
  the same rules as the relay image (a digest from the console, a tag from the environment
  file). Chromium runs in kiosk mode as an unprivileged user with its own sandbox on; the
  container is read-only, without capabilities, with `no-new-privileges`, a pid and memory
  limit, and a seccomp profile that is Docker's default plus the namespace and chroot
  calls the Chromium sandbox needs, written by the gateway from its own copy. Chromium
  policy allows the upstream's origin and blocks every other URL, downloads, printing,
  developer tools, extensions, sign-in, sync, password saving, autofill, safe-browsing and
  metrics. Nothing of the session outlives the container.
- **Upstream TLS.** An https upstream is verified by Chromium against the system roots, or
  against the bundle pasted on the target, which is installed in the browser's certificate
  store for that session. Verification is never switched off.
- **Readiness.** The Applications page lists what a first application needs: a guacd
  address and a container runtime the service can reach, the same requirement as database
  access. It no longer asks for a domain, a public address or a certificate.
- **Audit.** `session.connect`, `session.start` and `session.end` with protocol `http`,
  as for a desktop; `app.session.*` and the per-request log go with the proxy. The
  recording is the pixel stream, replayable like a desktop's.
- **Limits.** A browser session is capped by `ZANSKAR_APPS_MAX_SESSIONS` (default 10),
  the way database sessions are, since each one is a Chromium.
- **Not in this version.** Resizing the browser after the session starts (the screen is
  the size the user's window had when they opened it), sound, file upload into the
  application, credential autofill from the vault, and running in the Compose stack or on
  Kubernetes, where the gateway has no container runtime; those deployments reach
  applications the way they reach databases: not yet.

## Consequences

- An operator enrols an application with its address and a policy, and it opens. No DNS,
  no certificate, nothing on the clients.
- The gateway host needs Docker or Podman reachable by the service user, the same drop-in
  as database access, and guacd on the runtime's default bridge, as the install guide
  starts it. The AWS reference install attaches guacd to that bridge.
- Each open application costs a Chromium: about half a gigabyte and a core under load.
  The cap bounds it.
- The user sees pixels: a page is a little softer than in their own browser and carries a
  remote desktop's latency. Every session is recorded and replayable, which the proxy's
  request log never gave.
- A breaking change for 1.5 and 1.6 installs that set an apps domain: the setting, the
  apps certificate and the label are dropped by migration 0032, and the applications
  themselves keep working through the browser. The upgrade note says so.
- The threat model's TB8 becomes the browser container: a hostile application can attack
  the browser, which is sandboxed, disposable and able to reach nothing but that
  application; it never sees the user's browser, the console's cookie, or the network.
- The second listener personality, the host dispatch and the apps certificate leave the
  code, and with them the open-redirect, cookie and rewrite surface the proxy carried.

## Alternatives considered

- **Keep the proxy and add the browser beside it.** Two models to explain, and the one the
  operator could not use stays in the manual; rejected by the operator.
- **A browser on the bridge without the relay.** One container fewer, but the browser
  could then reach the whole network on a renderer compromise, with only Chromium policy
  between them. The relay makes the network boundary a kernel boundary.
- **Headless Chromium streamed over its own debugging protocol.** No VNC and no X server,
  but a second streaming protocol beside guacd, with its own recording and clipboard
  handling, when the desktop path already does all of it.
- **Chromium without its sandbox (`--no-sandbox`).** Simpler, since Docker's default
  profile blocks user namespaces; rejected, because a renderer exploit would then own the
  browser process outright. The profile adds four calls and keeps the rest of the default.
