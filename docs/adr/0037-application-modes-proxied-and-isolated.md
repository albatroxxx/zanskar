# 0037. An application opens proxied in the user's own browser, or isolated in a full browser beside the gateway

Date: 2026-10-31

## Status

Accepted 2026-10-31. The owner chose the direction (two modes, the operator picking one per
application) and took the recommended answers to the questions at the end, after a review by
Fable 5.1 whose changes are folded in: the phase order, the relay work that *also reachable*
needs, and the hardening of the proxied mode below. Amends
[ADR 0034](0034-applications-isolated-browser.md) (isolated mode keeps its container per
session and becomes a full browser) and brings back, in a new shape, the reverse proxy of
[ADR 0033](0033-applications-identity-aware-proxy.md). Amended 2026-11-02: other endpoints, reached
through the relay as a SOCKS proxy rather than by server name, built before phase 2 (below).

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
- **Also reachable.** *Amended 2026-11-02 (below): built as other endpoints, browsable, through
  a SOCKS proxy.* An application gains an optional list of further origins (its
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
   3. *Also reachable*, with the relay routing by server name. About a week. *Built first, on
      2026-11-02, as other endpoints through a SOCKS proxy (the amendment below).*
   4. Ports.

## Amendment (2026-11-02): further origins as endpoints, reached through a SOCKS proxy

The owner asked for phase 3 before phase 2: an application is often several addresses (the
application, its API on another host, its sign-in page), and a person should browse all of
them in one session. Built for isolated mode, which is every application today; proxied mode
(phase 2) is not built and will need its own answer for more than one name.

- **Endpoints, not only background origins.** *Also reachable* becomes *Other endpoints*:
  an application keeps its upstream, the page the browser opens, and may name up to 31
  further origins, each with a name. The browser reaches all of them and shows them as one
  bookmarks folder named after the application, on the bar, when there is more than one
  origin; nothing opens at start but the upstream, since each tab costs a renderer. An
  endpoint is an origin, as the upstream is: no path (a bookmark with a path can come
  later). Each meets the address rules as it is saved (an IP literal) and when a session
  starts (a name); a forbidden answer refuses the session, a name that does not resolve
  leaves that origin out of the session, which opens and says so (`session.start`'s
  `unreachable_origins`). Taking an endpoint off an application ends its open sessions.
- **The relay is the browser's SOCKS5 proxy, not a router by server name.** Routing by the
  TLS server name, as planned above, fails twice. Two https origins that are IP literals on
  one port cannot be told apart, because a client sends no server name for an address, and
  the operator who reaches applications by IP on a LAN without DNS is the one ADR 0034 was
  for. And Chromium's HTTP/2 connection coalescing sends requests for one name over a
  connection opened for another when both resolve to one address (every origin resolves to
  the relay) and share a certificate (a wildcard), so a request would reach the wrong
  upstream. A proxy is asked for each host and port by name, so neither arises. The relay
  takes SOCKS5 CONNECT on the session network only, for exactly the origins' host:port
  pairs, and dials the address the gateway resolved for each when the session started; it
  never resolves a name. Chromium's `ProxySettings` policy names it, with `<-loopback>` so
  even loopback goes there; the resolver maps every name but the relay's to nothing.
  Measured against the 1.11.2 browser image before building: Chromium asks a `socks5://`
  proxy for each host by name, an IP literal too, and the resolver's catch-all must
  `EXCLUDE` the relay's address or the proxy is unreachable. Chromium's link-local bypass
  does not matter: the session network has no route anywhere.
- **The policy is built by the gateway** and passed to the browser whole, so it is tested
  where it is made: the allowlist names each origin exactly (`http://.host:port`, the dot
  meaning not its subdomains; an IP literal as written), prediction is off (it opened
  connections to pages nobody asked for) and WebRTC goes through the proxy or nowhere.
- **Mixed versions keep working.** The relay still forwards the upstream's own port and the
  resolver still maps its name to the relay, so a browser image pinned from before opens the
  upstream as it did; the entrypoint writes its own policy when the gateway sends none, so a
  new image under an older gateway does too.

## Amendment (2026-11-03): an application's dependencies load from anywhere public

**This widens what an isolated session can reach.** From this change, a session's relay lets
the application's pages fetch from any public address on port 80 or 443, and every
application already enrolled takes that default when the gateway is upgraded (migration
0048). An owner who wants a session held to its origins, as every session was before, sets
the application's dependencies to *its origins only*.

The owner found that applications enrolled by their main address came up unstyled: their
pages load stylesheets, scripts, fonts, images and API calls from third parties (a CDN, a
font service, an API on another host), which the relay refused because only the origins
were listed. Listing each is not practical; an application should work whole, while opening
anything in a tab stays limited to the approved addresses.

- **Two layers, two jobs.** Chromium's `URLBlocklist` and `URLAllowlist` govern navigation
  only: the address bar, links, new tabs and frames. They never applied to a page's
  sub-resources, which the relay alone was refusing (proved at the relay's log before
  building: Chromium asked its SOCKS proxy for `cdn.jsdelivr.net:443` and was refused). So
  the policy stays as it is and keeps the person to the origins; the relay changes.
- **The relay's second rule.** A SOCKS CONNECT that matches no route is now accepted, under
  the application's `public` setting, when the port is 80 or 443 and every address the host
  resolves to is public: `ipspace.Reserved` says nothing of it. Loopback, link-local (the
  cloud metadata services), private ranges, unique local, shared address space, multicast,
  the documentation and benchmarking ranges, and the IPv6 ranges that carry an IPv4 address
  inside them (NAT64, 6to4, Teredo) are refused, with the reason at debug. The relay
  resolves the name once itself, checks every answer and dials the one it checked, IPv4
  first, never the name again. A dependency on a private address, on another port, or
  embedded as a frame is listed as an endpoint, as before.
- **The browser's own traffic stays in.** Seen at the relay with every policy and flag
  applied: Chromium still asks for `accounts.google.com`, `update.googleapis.com` and
  `clients2.google.com`. No application's page depends on them, so the relay refuses them
  under `public` too; an application that signs in with Google lists `accounts.google.com`
  as an endpoint, which it needs for the sign-in page anyway.
- **The setting.** `app_dependencies` on an application: `public` (the default) or
  `origins`. In the console, *Dependencies: Any public address / Its origins only*, on the
  detail page, in the configuration file and in the Terraform provider. Narrowing an
  application to its origins ends its open sessions, as removing an endpoint does; the
  session's start event says which it ran with (`dependencies`).
- **The relay logs at the gateway's level.** At debug it says what each request asked for
  and what it decided, so an operator can see what a page fetches and why something was
  refused; the gateway passes `ZANSKAR_LOG_LEVEL` to the relay by value.
- **No image change.** The relay is the gateway's own image, so this ships with the
  gateway; the browser image is untouched.

Rejected: resolving dependencies through a list of allowed public hosts per application
(the list the owner does not want to maintain); any port to a public address (web
dependencies are on 80 and 443, and a wider rule makes the relay a general proxy); letting
frames through (a frame is a navigation to Chromium's policy, which cannot tell a frame
from a tab, and a page that may frame anything can show anything).

## Amendment (2026-11-03, later): the relay inspects, so frames, private hosts and any port work

**Under *Dependencies: Any public address*, the session's relay now reads the session's HTTP
in clear, cookies and tokens included.** It terminates TLS with a certificate authority made
for that session alone and verifies the real origin itself. It logs the host and the kind of
each request it refuses, never a path, a header or a body. An application whose session must
not be decrypted is set to *Its origins only*, which is unchanged from before: a blind tunnel
to the listed origins and nothing else.

The owner asked for the three limits of the amendment above to go: frames from third parties,
dependencies on private addresses, and ports other than 80 and 443, each of which still needed
an endpoint listed. A SOCKS tunnel cannot tell a frame from a tab, cannot tell a page's fetch
from a raw TCP connection, and cannot say what asked for a refused host. An HTTP proxy that
inspects can.

- **The relay is an HTTP proxy that inspects.** Chromium's `ProxySettings` name it as an
  `http://` proxy. A plain `http://` request arrives whole. For `https://` the browser sends
  `CONNECT host:port`; for a destination the rules allow, the relay answers, looks at the first
  byte (a TLS record under `wss://`, `https://`; plain HTTP under `ws://`), and, for TLS,
  presents a leaf certificate for that host signed by the session's CA, speaks HTTP/1.1 with
  the browser, and forwards each request to the real origin over TLS verified against the
  system roots, or against the application's CA bundle for its own origins, dialling the
  address the gateway pinned for an origin or the address the relay checked for anything
  else, never a name again. The session's CA (an ECDSA key made when the session starts) is
  trusted by that session's browser alone, through the certificate store the entrypoint
  already fills (`CA_PEM`); its key lives in the relay's memory and dies with the container.
  The upstream's own CA bundle no longer goes to the browser: the relay verifies the upstream.
- **A page opens only at the origins; everything else is a dependency.** Chromium sends
  `Sec-Fetch-Dest` and `Sec-Fetch-Mode` with every request to a secure destination. A
  top-level document (`navigate` + `document`: the address bar, a link, a new tab, a popup, a
  redirect's end) is allowed at the upstream and the endpoints and answered with the relay's
  own *blocked* page anywhere else, which is also how a person sees it was Zanskar that said
  no. A frame, a script, a style, a font, an image, a fetch, a WebSocket, a worker is a
  dependency and goes through under the dependency rules. Chromium's `URLBlocklist` catch-all
  goes under *Any public address*, since it blocks frames too (checked on the rig before
  building); the scheme blocks (`chrome://`, `file://`, `javascript:`, `view-source:`,
  `devtools://` unless granted) stay. Under *Its origins only* the catch-all and the allowlist
  stay as they were.
- **Frames.** A frame from a public host is a dependency: reCAPTCHA, a payment frame, an
  embedded video load. A frame's own navigations are frames, so a page framed from elsewhere
  cannot become a tab; `window.open` is a document, so a popup to a third party is still
  refused unless the origin is listed.
- **Ports.** For a public host the relay only ever speaks HTTP on whatever port the page
  named, so there is no port to restrict: a browser can make nothing but HTTP through it. The
  80/443 rule of the amendment above goes with the blind tunnel it guarded.
- **Private addresses: learned, then allowed.** A dependency on a private address stays
  refused until an administrator allows it, because a page that may reach any private host
  reaches the gateway's neighbours too. The relay says what it refused, one aggregated line
  per destination per minute (`apprelay dependency refused`: host, port, why, what asked —
  the `Sec-Fetch-Dest` — and the page's origin, never its path), and the gateway reads those
  lines from the container's log every 30 seconds and once more before it removes the
  container, keeping them per application. The application's page in the console shows them
  under *Blocked dependencies*: for a private host, **Allow** adds `host:port` to the
  application's private dependencies, reachable for dependencies and frames, never as a page,
  with no bookmark; a loopback, link-local or metadata address, or the gateway's own, is
  shown with a warning and cannot be allowed. *Private networks* (`10.20.0.0/16`) lets an
  administrator allow a whole network instead of clicking each host. In the API,
  `app_private: {networks: [...], hosts: ["cdn.corp:443"]}` on an application, in the
  configuration file and the Terraform provider likewise; what was learned is read-only
  through the API. A blocked page open (a person typing a third-party address) is kept the
  same way: it is worth an auditor's look.
- **Learning through the container's log** rather than a listener on the bridge: the gateway
  already owns the containers through the Docker CLI, a log line costs the relay nothing, and
  nothing new listens where other sessions' relays could reach it.
- **What the relay keeps from itself.** Every server the relay runs has a header timeout and
  a header size cap; the block page is rendered through `html/template`; the relay's own
  addresses are private, so a request aimed at them is refused by the rule; the browser's own
  service hosts stay refused; a request the proxy cannot parse is dropped.

Residuals, stated: Chromium sends no `Sec-Fetch` headers to an insecure (`http://`)
destination, so a plain-http third party framed by a plain-http page cannot be told from a
navigation and is refused as one (a secure page cannot frame plain http anyway); a browser
image pinned from before 1.12 verifies an `https` upstream itself and no longer gets its CA
bundle, so such an upstream under a private CA needs the 1.12 image or newer; a private name
resolves through Docker's embedded DNS, that is, the host's resolver, as the upstream's did;
an application that pins its own certificate in script cannot be inspected and is set to *Its
origins only*; the session's CA key travels to the container as the VNC password and the
relay's table do, in the container's environment, readable to root on the host and to no one
else.

Rejected: a browser extension with `declarativeNetRequest` rules that block `main_frame` and
pass `sub_frame` (delivering a force-installed extension under the session's policy needs an
update server and a signed package, and the policy that blocks extensions would have to open;
fragile where the proxy is plain); allowing private hosts by heuristic (the upstream's own
/24, or static loads only), which is a server-side request forgery into the gateway's network
on a page's say-so; a bridge-side endpoint the gateway polls for refusals (one more listener,
and the gateway cannot reach a bridge address on every host it runs on).
