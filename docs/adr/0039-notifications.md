# 0039. Notifications follow the audit log, to a signed webhook or by email

Date: 2026-11-03

## Status

Accepted 2026-11-03. The owner asked for everything the 2026-11-03 live audit recommended;
this is its idea 3 ("approvals out of the console").

## Context

A request for access waits in the console until an approver happens to open Approvals; the
live gateway's Keycloak stopped answering its sync for hours and nobody was told. The gateway
already ships every audit event to a SIEM (`audit.Exporter`, ADR 0008): a sink per
destination, a checkpoint per sink in `audit_export_state`, at-least-once delivery, backoff.

People are told things in many places: Slack, Teams, Mattermost, Google Chat, PagerDuty,
email. The vendor-neutral rule (2026-10-30) says the standard path first.

## Decision

1. **A notification is an audit event, worded.** A notifier follows the audit log as the SIEM
   export does, with a checkpoint per channel (`notify:<id>` in `audit_export_state`), and
   sends the events a channel asked for. Nothing is sent that the log does not hold, a
   restart loses nothing and sends nothing twice past the checkpoint, and a failing channel
   backs off without holding the others. A new channel starts at the newest event, never at
   the start of history.
2. **Two kinds of channel, both standard.** A *webhook*: an HTTPS POST of JSON whose `text`
   is the sentence, beside a `zanskar` object (kind, event id, time, link), signed as the SIEM
   export signs (`X-Zanskar-Timestamp`, `X-Zanskar-Signature: sha256=<hmac>`). Slack's and
   Mattermost's incoming webhooks show `text` as it is, so they need no adapter; anything
   else verifies the signature and reads the object. *Email*: SMTP, STARTTLS (or TLS on
   465), authentication only over TLS, to a list of addresses.
3. **What a channel can ask for.** Access requested; access decided (approved, denied,
   revoked); a session terminated by an administrator; a sign-in provider's sync failing; a
   recording lost; new sessions refused for a full disk. Each message carries a link to the
   console page that acts on it; acting there still needs a sign-in and its second factor.
   There is no approve-by-link: a link that grants access is a bearer token in an inbox.
4. **Secrets sealed.** The webhook URL (an incoming-webhook URL is itself the credential), its
   signing key and the SMTP password are sealed with the key ring, AAD
   `notification_channels/<id>`, the key version beside them, and listed for `zanskar key`.
   The API never returns them; it says whether one is stored.
5. **Where it sends.** HTTPS only for webhooks, no redirect followed (a 307 re-posts the body
   elsewhere), and never to a loopback, link-local (cloud metadata) or unspecified address,
   checked at dial time so a name rebound later is refused too.
6. **Bounded.** One message per event; past 20 events in one pass a channel gets the first 20
   and one line saying how many more, so an incident does not flood an inbox.

## Consequences

- Approvers hear of a request without the console open; an outage of single sign-on reaches
  someone.
- A channel added while events flow misses nothing after its creation and replays nothing
  before it.
- Teams, Google Chat and PagerDuty need their own payloads: a relay that verifies the
  signature and reshapes the JSON, or a later adapter beside the standard path.
- A message names people and targets; a channel is as sensitive as the audit log's export,
  and only administrators manage channels (each change audited).

## Amendment, 2026-11-03: the link opens the request, and approving asks for a code

The live audit's idea 3 asked for an approve link gated by MFA. A link still grants nothing,
for the reason above; what changed is where it goes and what approving takes.

- A request's message, asked or decided, links to that request
  (`/admin/approvals?request=<id>`): it opens in the approve dialog while it waits, and the
  page says what became of it (approved by whom, when) when it no longer does.
  `GET /access-requests/{id}` serves it, administrators only.
- Approving asks an approver who has an authenticator for a code proved in the last 5
  minutes (`step_up_required`, the host actions' rule, ADR 0032). The dialog shows a code
  field and approves once the code is in; the console command line asks for a code and runs
  the line again. A stolen session or a forwarded link alone cannot grant access. An
  approver without one (single sign-on, whose provider proved them at sign-in) is not asked.
  Denying and revoking take access away and never ask.
- The setting *Approving asks for a code* (`access.approve_step_up`, Settings › Sign-in) is
  on by default. Switching it off asks for a code too, or a stolen session could switch it
  off and approve.

## Amendment, 2026-11-03 (later): one mail server, apart from the channels

Each email channel carried its own SMTP server, account, password and sender, so adding a
second list of recipients meant typing the server again, and a password lived in every
channel. The owner asked for the server to be set once, apart from the people.

- **The mail server** (`email_server`, migration 0051): host, port (587 STARTTLS, 465 TLS),
  an account with its password sealed by the key ring, and the sender. Set, tested with one
  message to an address of the administrator's choosing, and removed under Settings ›
  Notifications › Email server; `GET`, `PUT`, `DELETE` and `POST …/test` on
  `/admin/notifications/email-server`; each audited (`notify.email_server.*`), the password
  never in the API or the log.
- **An email channel names its recipients alone.** `smtp_*` and `from` are no longer taken
  on a channel. With no mail server set, an email channel's deliveries fail saying where to
  set one; the test button says the same.
- **Upgrading.** At its first start after the upgrade the gateway adopts the first email
  channel's server, password included, as the mail server, and takes the server out of every
  email channel, which keeps its recipients (logged, not audited: no person did it). A channel
  that still carries a server, because the adoption has not run, sends through its own until
  it is saved again.
