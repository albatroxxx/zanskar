# 0037. An application opens proxied in the user's own browser, or isolated in a full browser beside the gateway

Date: 2026-10-31

## Status

Accepted 2026-10-31. The owner chose the direction (two modes, the operator picking one per
application) and took the recommended answers to the questions at the end, after a review by
Fable 5.1 whose changes are folded in: the phase order, the relay work that *also reachable*
needs, and the hardening of the proxied mode below. Amends
[ADR 0034](0034-applications-isolated-browser.md) (isolated mode keeps its container per
session and becomes a full browser) and brings back, in a new shape, the reverse proxy of
[ADR 0033](0033-applications-identity-aware-proxy.md).

## Context

Since 1.7.0 every open application is a Chromium in a container of its own, streamed as
pixels through guacd (ADR 0034). The owner's live gateway (1 GB, 1 vCPU) fits about one
such session, and the docs priced each at half a gigabyte. Two things followed from walking
the live console:

- **Cost.** Measured on 2026-10-31 with the published 1.9.0 browser image, started exactly as
  the gateway starts it (limits, seccomp profile, 1600x900):

  | One session, container per session | Memory (cgroup) |
  |---|---|
  | A plain page (nginx) | 185 MB |
  | A JavaScript application (Grafana's login page) | 250–280 MB |
  | The same with `--enable-low-end-device-mode` | 230–250 MB |
  | `--renderer-process-limit=1` on top | no further change |

  About 150–180 MB of each is Chromium's own machinery (browser, GPU, network and storage
  processes), repeated per session; the rest is the application's page.
- **Engineers cannot work in it.** Kiosk mode hides the address bar, tabs and developer
  tools. A QA or application engineer who opens an application through Zanskar cannot see
  the URL, open a second page or read the network panel, so cannot troubleshoot. An
  application behind single sign-on (Grafana redirecting to Keycloak) has never opened at
  all: the browser may reach the application's origin and nothing else.

Three directions were weighed, with an independent review (Fable 5.1):

- **One shared browser, an isolated profile per session** (Chromium browser contexts over
  the DevTools protocol). Measured the same day: 182 MB with no session, then about 115 MB
  per session on Grafana (1 session 333 MB, 5 776 MB, 10 1.35 GB), a new session in well
  under a second. About half of today's cost at ten sessions. Rejected: the container per
  session is the wall between one person's session and another's, and with one browser a
  single sandbox escape in a page reaches every user's open applications; the session cap
  stops being a security control. A headless browser also has no address bar, tabs or
  developer tools, so the console would rebuild them and give developer tools a filtered
  channel into the one browser everyone shares.
- **The user's own browser, through Zanskar's proxy.** A few megabytes per session, the
  user's real browser with its real developer tools, instant. It gives up the pixel
  recording, shadowing, download and clipboard control, and confinement to one origin.
  ADR 0033 built this and lost it to operability, not security: an apps domain, wildcard
  DNS and a certificate no public authority issues for a private name, before one page
  loaded.
- **Today's container per session, as a full browser.** Keeps every property of ADR 0034;
  costs what it costs today.

The owner chose two modes: the proxy for applications the organisation trusts, and the
isolated container, now a full browser, where recording and control matter.

## Decision

**Each application has a mode, set by the operator: proxied (the user's own browser,
through Zanskar's reverse proxy) or isolated (a full browser in a container per session,
streamed). Isolated is the default, and a grant can require it.**

### Mode and policy

- An application target gains `mode`: `isolated` (default; today's behaviour) or
  `proxied`. Isolated needs nothing beyond what ADR 0034 needs, so every application can
  always be opened isolated.
- A grant gains **Require isolated**. A person whose admitting grants require it opens a
  proxied application isolated; otherwise the application's mode decides. As with every
  grant term, the strictest wins where grants overlap (ADR 0036).
- The console says what a mode gives up where it matters: a **Proxied** badge on the
  application, in the access portal and on its sessions, with *not recorded* on the
  session rows. Proxied is never chosen implicitly.

### Proxied: addressing

The address is the whole question; ADR 0033 failed there. Each application gets a name
under the console's own host, or a port on it, depending on how the gateway is deployed:

- **Names (recommended): `https://<app>.<console host>`**, routed by the `Host` header
  through the gateway's one listener.
  - *Behind a TLS proxy* (Caddy, nginx, a load balancer; the owner's own instance): the
    proxy terminates TLS for `*.<console host>` and forwards to the gateway as it forwards
    the console. With Caddy this is one on-demand TLS block whose `ask` endpoint is the
    gateway's (`GET /api/v1/apps/tls-ask?domain=`, true only for enrolled applications),
    plus one wildcard DNS record. No wildcard certificate: each name gets its own.
  - *Managed TLS*: the gateway's Let's Encrypt support (ADR 0021, amended) orders a
    certificate per enrolled application name. Its host policy and `Covers` become dynamic
    (today they are built once from the configured names). Let's Encrypt allows 50 new
    certificates per registered domain a week and 5 for the same name a week, so the cache
    is kept and the failure backoff honoured; a renamed or re-enrolled application must not
    order again in a loop. Needs the wildcard DNS record and public reachability.
  - *The `ask` endpoint* is unauthenticated by nature, so it answers only for
    `<label>.<console host>`, by label, rate-limited, and only to the address the TLS proxy
    connects from; the Caddy example sets `on_demand_tls { interval 2m burst 5 }`.
  - **The application must know its new address.** `Location` rewriting does not reach the
    absolute URLs an application builds from its own configured address, nor the redirect
    URIs it registered with its identity provider. The operator sets the application's
    external URL (Grafana's `root_url`, Jenkins' URL) to its proxied name, and registers
    that name with the provider; the console says so when the mode is set, and the
    readiness checklist asks.
  - Why the console's own domain is safe now, where ADR 0033 required another: both of the
    console's cookies carry the `__Host-` prefix whenever it is served over HTTPS, proxy-TLS
    mode included (the session cookie, `auth/sessions.go`; the OIDC state cookie,
    `idp/oidc`), and the session cookie is HttpOnly. A `__Host-` cookie is never sent to a
    subdomain and cannot be set by one, so an application can neither read nor plant it.
    Subdomains are same-site, so SameSite=Strict does **not** stop a request from an
    application to the console, and the console's cookie travels with it; the CSRF check
    does: `sameOrigin` (`auth/middleware.go`) refuses `Sec-Fetch-Site: same-site`, and
    falls back to `Origin` equal to the console's. Its one gap is a request carrying
    neither header, which it takes for a non-browser client; browsers always send one of
    them on such requests, and with proxied names on, the console refuses a request that
    carries the session cookie and neither header. WebSockets keep the library's origin
    check, so a page on a subdomain cannot open `/ws/*`; the console sends
    `frame-ancestors 'none'`, and adds `Origin-Agent-Cluster: ?1` (Chrome already ignores
    `document.domain`; this closes it in Firefox). The console's HSTS is already
    `includeSubDomains`, so every application name is HTTPS-only in a browser that has
    seen the console.
  - Residuals, accepted because proxied applications are trusted ones: an application can
    set cookies for the parent domain (`Domain=<console host>`). The console ignores them,
    but a hostile application could plant enough of them to make the console answer 431
    until the user clears cookies, and sibling applications can overwrite each other's
    own cookies. An application that is not trusted is opened isolated.
- **Ports (fallback): `https://<console host>:<port>`**, for a gateway that serves TLS
  itself and has no DNS (the LAN operator of ADR 0034). Each proxied application gets a
  port from a configured range (`ZANSKAR_APPS_PORTS`, e.g. `9001-9100`), served with the
  console's certificate, which is valid for the host whatever the port; a self-signed one
  costs one more browser warning per port. Ports are separate origins but share one
  cookie jar: the proxy strips Zanskar's cookies inbound and prefixes the names of the
  cookies an application sets, but it cannot see cookies a page sets from JavaScript, so
  two applications on ports can read each other's script-set cookies and one can plant
  cookies on another (login CSRF). Ports are for one application, or for applications
  that trust each other; the console says so when the range is set.
- Behind a TLS proxy, ports are not offered: the gateway holds no certificate there.

### Proxied: the session

Reused from ADR 0033 (`internal/apps` at `bf59220`, about 1,400 lines):

- **Hand-off.** *Open* in the access portal checks policy as a connect does, then
  redirects to the application's address with a one-time code bound to the person, the
  application and the grant; the gateway exchanges it for a host-only cookie for that
  address (`__Host-` on names), SameSite=Lax so the identity provider's return
  navigation carries it, as ADR 0033's did; Lax is not sent on a cross-site WebSocket
  upgrade or POST, so neither can ride it. The console cookie never travels to an
  application, and the strip rule removes every cookie the gateway sets, by every name.
- **Every request** is checked against that session: live, within its limits, the grant
  still admitting it. Withdrawing access, terminating the session or its limits end it at
  the next request; WebSockets are closed. Idle means no requests: an application that
  polls is never idle, so its maximum is what bounds it.
- **Proxying rules.** The upstream comes from the target alone, never from the request.
  Zanskar's cookies and any client-supplied identity headers are stripped; `Location` is
  rewritten; WebSockets and HTTP/2 pass. An https upstream is verified against the system
  roots or the target's CA bundle, failing closed.
- **Audit.** `session.connect`, `session.start` and `session.end` with protocol `http` and
  `mode: proxied`, as today; a per-request log (method, path without the query, status,
  bytes, duration; never bodies), outside the audit chain (ADR 0029), stored as a third
  recording format beside asciicast and Guacamole: JSON lines with a content type of its
  own, so recording storage, S3, retention, backup and the recording routes take it
  unchanged. The Sessions pages call it a *request log*, never a recording.
- **What it is not.** No recording, no shadowing; downloads, uploads, printing and the
  clipboard are the user's own browser's, and the application says so. The application's
  single sign-on works as it would directly once its external URL is the proxied name: the
  user's browser reaches the identity provider itself.

### Isolated: a full browser

The container per session, internal network, relay, seccomp profile and recording of ADR
0034 stay. What changes:

- **Chromium's own interface.** Kiosk mode goes: the session shows Chromium's address bar,
  tabs, back, forward and reload. The console's Back / Forward / Reload / Home bar goes
  with it.
- **Also reachable.** An application gains an optional list of further origins (its
  identity provider, an API on another host). The relay forwards them, the resolver maps
  them, and Chromium's `URLAllowlist` names them, together, so the address bar and new tabs
  reach the application and that list, nothing else. The relay today maps one listener to
  one upstream (`apprelay`, `Forward{Listen, To}`), and two https origins on 443 would
  collide on its one internal address, so it learns to route by the TLS server name
  (peeking at the ClientHello, decrypting nothing) and, for http, by `Host`. Each extra
  origin passes the same address rules as an upstream; a public one (a hosted identity
  provider whose addresses rotate) is resolved when the session starts and pinned to that
  set.
- **Developer tools by grant.** A grant gains **Developer tools** (off by default). Granted,
  the session's Chromium policy sets `DeveloperToolsAvailability` to 1 and allows
  `devtools://`; otherwise it stays 2. Safe because the container is that person's alone:
  the tools see that session and nothing else, and cannot reach the gateway or guacd past
  the relay; they let the person do by hand what the page could do. Saving from the tools
  must honour the download block; verified before it ships.
- **Still blocked:** downloads, printing, extensions, browser sign-in, sync, saved
  passwords and autofill, and, named explicitly beside the blanket rule, `chrome://*`,
  `file://*`, `javascript:*` and `view-source:*` (`chrome://version` would show the
  resolver rules: harmless, but not the user's business). Clipboard and recording as
  today.
- **Lighter by default:** `--enable-low-end-device-mode` (about 10% less, measured).

### Readiness and limits

- The Applications checklist gains, when an application is proxied: a wildcard name that
  resolves to the gateway (names), or the port range reachable (ports), and a reminder of
  the application's external URL.
- Choosing a mode shows its cost beside it: the measured 250–280 MB a session for isolated,
  with the cap; a few megabytes for proxied.
- `ZANSKAR_APPS_MAX_SESSIONS` caps isolated sessions only; proxied ones cost almost
  nothing. A default derived from the host's memory, rather than a flat 10, is worth
  measuring once isolated sessions are lighter.

## Consequences

- A 1 GB gateway serves applications to its users through the proxy; isolated sessions
  stay possible where memory allows.
- Engineers troubleshoot through their own browser (proxied) or a full one with developer
  tools (isolated), each granted.
- The operator chooses, per application, between recording and cost; the console never
  hides which was chosen.
- The proxy comes back with its risks: a hostile or compromised proxied application runs in
  the user's browser like any website. Proxied is for applications the organisation trusts.
- The docs grow: deploy.md and the guide's Applications sections, the Caddy example, the
  OpenAPI for the new fields and routes, the readiness checklist.

## Alternatives considered

- **One shared browser, a profile per session** (above): half the memory, one sandbox
  escape from every user's session. Rejected.
- **A headless browser streamed over the DevTools protocol** instead of Xvnc and guacd, per
  session: less CPU and latency, resize after opening; the memory barely moves. A later
  amendment, not this decision.
- **A warm pool of containers:** faster start, no less memory; a browser cannot be
  re-pointed once its resolver and policy are written. Only if start time becomes the
  complaint.
- **A lighter engine** (WebKitGTK, Firefox, Servo, Ladybird): a modern application costs
  150–250 MB in any engine, and the applications in question are tested on Chromium.
- **A path under the console** or service-worker rewriting: shares the console's origin
  and cookie; rejected in ADR 0033 and still.
- **A local client tunnel** (`zanskar app grafana` → `http://127.0.0.1:port`): no DNS, no
  certificate, true isolation of origins, but software on every user's machine. Later, for
  developers, if asked for.

## Answers (2026-10-31)

The owner took the recommendations; Fable's review changed the phase order.

1. **Names and ports**, names first. The owner's instance (behind Caddy) needs names; a LAN
   gateway without DNS needs ports.
2. **Proxied downloads, uploads and printing** are the user's browser's, said on the
   application.
3. **A 1 GB gateway offers isolated mode**, with the measured cost beside the choice.
4. **The per-request log is a recording format**, stored and retained with recordings.
5. **Developer tools in isolated mode** are a grant condition, off by default.
6. **Phases:**
   1. Isolated as a full browser: Chromium's toolbar, developer tools by grant, the
      explicit blocklist, the lighter flag. Days.
   2. Proxied by name: the memory fix the owner's own instance needs. About three weeks
      with ADR 0033's code as the base.
   3. *Also reachable*, with the relay routing by server name. About a week.
   4. Ports.
