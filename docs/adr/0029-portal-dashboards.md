# 0029. Each portal lands on a dashboard, scoped to the portal's role

Date: 2026-10-15

## Status

Accepted.

## Context

After sign-in the console drops the user straight into a list: hosts for an administrator,
events for an auditor, targets for a user. Nothing answers the first questions a signed-in
person actually has — is anything live right now, is anything waiting on me, is anything
wrong — without clicking through pages. The logo in the sidebar already returns to each
portal's first page (`homeFor`), so whatever that first page is becomes the natural home.

One shared dashboard page is ruled out by 0006 (roles): an auditor-only account is refused
on every connect-facing route, and a user must never receive fleet-wide numbers — telling a
user who can reach three machines that forty-seven exist is disclosure. Whatever the
dashboard shows has to be computed under the caller's role, on the server.

A dashboard must also not become a reason the gateway gets slower or the audit chain gets
noisier. The audit portal's reads are themselves audited (`audit.read`); a page that polls
an event list would flood the chain it exists to protect. And `audit.verify` walks the whole
chain, so it cannot run on every page load.

## Decision

**Three landings, one per portal, each behind the portal's existing guard.**

- `/admin` lands on an administrator dashboard. Hosts moves to `/admin/hosts`.
- `/audit` lands on an auditor dashboard. Events moves to `/audit/events`, the path it
  already has inside the admin console.
- The user portal keeps **Targets as its landing page**. Connecting is what a user signs in
  to do; a page in front of that is a click added to every session. Instead the Targets page
  gets a slim overview strip — my open sessions, my pending requests, grants
  expiring soon — fed by the `/api/v1/me/...` routes that already exist and are already
  scoped to the account.

**Two new read-only endpoints, one per reviewing role, both returning counts only.**

- `GET /api/v1/admin/overview` (admin): open and last-24h session counts, pending access
  requests, targets needing attention (host key pending or changed, a certificate pin
  awaiting confirmation), and 24-hour audit tallies (failed logins, refused connects,
  failures overall). The rest of the admin dashboard reuses routes that already exist:
  `system/status`, `tls`, `storage`.
- `GET /api/v1/audit/overview` (admin or auditor): the session counts, 24-hour event
  tallies, and recording views and downloads in the last 24 hours.

Counts are not content: no event, session or target data leaves the server, so reading an
overview records **no** `audit.read` event. That is this ADR's line to draw, and it matches
how the console already behaves — the pending-approvals badge the admin sidebar polls reads
a list without writing an event, because only the audit pages' reads are audited reads.
Anything on a dashboard that lists rows (recent events, open
sessions) loads through the existing audited endpoint, once per page open, never on a poll.
Chain verification stays behind its own endpoint and runs from a button, never on load.

The open-session count is the database's view (`ended_at IS NULL`), the same number the
Sessions pages show, so the tile and the page it links to can never disagree. After a crash
of another gateway process both may include a session until it is reconciled, which is the
existing behaviour of the Sessions list.

**The dashboard look follows the console: tiles and short lists, no charts.** Every number
links to the page that already manages the thing it counts; the dashboard owns no actions of
its own except follow-a-link.

## Network scoping, honestly

A motivation for portal-prefixed paths is a reverse proxy or WAF restricting the admin
console to certain source addresses. Both new endpoints sit under their portal's API prefix
so one path rule covers the page and its data: `/admin` + `/api/v1/admin/` and `/audit` +
`/api/v1/audit/`.

That rule scopes less than it appears to, and this ADR does not pretend otherwise. `/admin`
is a client-side route of the same SPA bundle everyone downloads; blocking it stops a page
refresh, not the API. And most administrative **writes** live outside the prefix —
`POST /api/v1/targets`, `/credentials`, `/access-policies`, `/groups`, approve and deny on
`/access-requests`, `terminate` on `/sessions` — because those resources are shared with
other roles for reading. A path rule on the two prefixes therefore restricts the console
shell, system lifecycle, settings and these overviews; it does **not** confine the admin
role to allowed addresses. Confining the role needs either moving admin mutations under the
prefix (a breaking API change) or a role-aware source-address check in the gateway itself.
Both are out of scope here and left for their own ADR if asked for.

## Consequences

- Sign-in and the logo land on the dashboard in the admin and audit portals; bookmarks to
  `/admin` and `/audit` now show the dashboard, and Hosts and Events are one click away at
  their new paths. An admin following an old `/audit` link is still redirected into the
  admin console, now to its dashboard.
- Two more unauthenticated-refused, role-guarded GET routes to document and test; neither
  writes, neither records audit events, both answer `Cache-Control: no-store`.
- The overview queries are counts over indexed columns (`audit_events_ts_idx`,
  `access_sessions_open_idx`); no new migration. On SQLite they run one after another on the
  single connection, never alongside an open cursor.
- The user portal gains no new backend surface at all.
