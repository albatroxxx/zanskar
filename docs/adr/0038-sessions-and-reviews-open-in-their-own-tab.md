# 0038. Sessions, watches and recordings open in a tab of their own

Date: 2026-11-01

## Status

Accepted 2026-11-01. The owner asked for it ("a user can open only one session … an auditor
… needs to inspect multiple sessions at once") and asked for Fable 5.1 to be consulted; its
review is folded in below, with one change of ours (the record keyed by the link's address
instead of a nonce in it).

## Context

The roadmap deferred a multi-pane workspace because "browser tabs already do this". For
sessions they did not:

- **A session took the page it was started from.** The access portal's protocol buttons
  called `POST /connect` and navigated the same tab to `/terminal` or `/desktop`, the ticket
  in that tab's history state. A second session meant leaving the first, or opening the
  portal again in another tab by hand. Applications and database clients went the same way.
- **An auditor reviewed one thing at a time.** Watch (a live session, read-only) and Review
  (a recording) were links, so a Ctrl or middle click opened a tab, but a plain click took
  the list away, and the watch's own exits went *back*, which in a tab of its own goes
  nowhere.
- **Every tab was called "Zanskar"**, so several open sessions could not be told apart.

What a ticket is constrains the design (`internal/ticket`): 32 random bytes, valid 30
seconds, redeemed once, and only by the browser session and client address that asked for
it. It must not appear in an address, the history, a Referer or a log.

## Decision

**Sessions.** Each protocol on the access portal (SSH, WinRM, RDP, VNC, SQL client, an
application's Open, "as me", and each instance in an autoscaling group's chooser) is a plain
link with `target="_blank" rel="noopener noreferrer"` to `/connect?target=<id>&protocol=<p>`
(or `asg=`, `asg=&instance=`, and `own=1` for the user's own login). The address carries ids
only, which the page already shows. `/connect` is a page in the new tab that does what the
button did: it finds the target among the user's (`/me/targets`, which is also the check
that it may be reached), connects, asks for the user's own login when the slot wants it, and
opens the terminal or desktop in that tab with the ticket in its history state, as before.
The ticket never leaves the tab that asked for it. A click, a Ctrl or ⌘ click and a middle
click all open a tab; there is no `window.open`, so no pop-up blocker is involved, and the
console navigates to no address an API returned.

**No session started by a link from elsewhere.** A page that connects on load would let any
site that links to it start a recorded session under the visitor's name, which the connect
call's CSRF token prevents today. So a click on one of our links (its `click`, or the middle
button's `auxclick`) writes a record of the link's address and the time to `localStorage`;
the new tab uses up one record for its own address, if one is less than a minute old, and
only then connects by itself. Opened any other way (another site, a bookmark, a pasted
address, the browser's "open in new tab" menu, which sends no event) it shows the target and
a **Connect** button. The record is no secret: it proves only that a page of this origin made
the link moments ago, which another origin cannot write. Two clicks leave two records, for
two tabs. The page reads its record once per page load even when React runs its first steps
twice. The console's `frame-ancestors 'none'` keeps the Connect button from being clicked
through a frame.

**Watches and recordings.** Watch and Review (and the recording links in Sessions and
Events) open in a tab of their own, the list staying where it was. They were already
addressable (`/audit/shadow/:id`, `/…/recordings/:id`); leaving a watch now goes to the
Sessions list of the watcher's portal instead of back.

**Names.** Session, watch, recording and connect tabs are titled after what they show
(`web-01 · SSH · Zanskar`, `Watching web-01 · Zanskar`, `Recording · alice on web-01 ·
Zanskar`). Links that open a tab keep their terse visible text; their accessible name adds
", opens in a new tab".

**What stays in place.** Signing in, the credential and access-request dialogs (they belong
to the tab that connects, or to the list), a failover to another instance (the same
session's tab), Terminate, the admin's edit dialogs and pages, Settings, signing out.

## Consequences

- A user runs several sessions at once, each in its tab; the list stays put, and its count of
  open sessions is read again whenever its tab is looked at.
- Outcomes of a connect (a refusal, a lapsed grant, no healthy instance) show in the new tab,
  not the list. A lapsed grant says so there and points back to Targets for the request.
- "Back to targets" at the end of a session stays: a tab cannot count on closing itself in
  every browser. A reload of a session tab behaves as it did before this change.
- The end-to-end suite now drives a session in a tab of its own, two at once, and the
  `/connect` page opened without a click; the old guarantee holds (a fresh `/terminal` goes
  back to the targets).
- No gateway change.

## Alternatives considered

- **Open a blank tab on click and hand it the ticket** (`postMessage`, `BroadcastChannel`, or
  the copy of `sessionStorage` a new window may get). The connect call and its prompts would
  run in the opener while focus sits in an empty tab, which must be closed again on a
  refusal, and the ticket would cross windows for no gain.
- **A one-time nonce in the link's address** (Fable's first proposal). It works, but the
  address must be rewritten at the click; keying the record by the link's own address keeps
  every link static and serves two clicks with two tabs.
- **`window.opener` or `document.referrer`** to tell our own links apart: `noopener` and the
  console's `Referrer-Policy: no-referrer` remove both, on purpose.
