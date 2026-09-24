# 0018. Just-in-time access approvals (PIM)

Date: 2026-09-24

## Status

Accepted

## Context

Zanskar today is a privileged **access** manager (PAM): it brokers sessions to hosts and
databases, holds the credentials so users never see them, evaluates access policies, and
records and audits every session. What it is not, yet, is a privileged **identity** manager
(PIM). Access is *standing*: if a policy makes a user eligible for a target, that user can
connect to it at any time inside the policy's time windows, with no request and no approval.
There is no just-in-time elevation, no approval workflow, and no time-bounded grant. "JIT
access approvals" was scheduled for the Phase 4 "Enterprise" roadmap; the decision has been
taken to bring a slice of it into v1.0, so the product ships with least-standing-privilege as
a first-class capability rather than a later add-on.

The bar for v1 is deliberately drawn tight so it is reachable: **just-in-time, approved,
time-bounded access.** A user who is *eligible* for a target holds no standing access to it;
they request access with a reason and a duration, an approver grants or denies, and an
approved request becomes a grant that expires on its own. Access reviews / recertification,
delegated and multi-step approver chains, notifications, SCIM, and automated credential
rotation are real PIM features but are **not** in this slice.

The design must fit what already exists rather than fork it: the policy engine
(`policy.Evaluate` returning a `Decision`), the connect gate (`connect.issueTicket`), the
hash-chained audit log, the session registry, and the RBAC roles (admin / auditor / user).
Standing access must be entirely unaffected for policies that do not opt in.

## Decision

Add an **eligibility → request → approval → time-bounded grant** layer on top of policies,
and gate connect on an active grant only for policies that opt in.

**Eligibility, not standing access.** A policy gains a boolean `require_approval` (default
`false`). A policy with `require_approval = true` grants *eligibility*: it defines who may
**request** which targets/ASGs over which protocols, inside which time windows, up to a
maximum duration — but it confers no standing access on its own. Existing policies keep
`require_approval = false` and behave exactly as today; there is no behavioural change until
an admin opts a policy in. Access remains a **union**: if any standing policy already grants a
user a target, that path wins and no approval is required; approval is required only when the
user's *sole* route to the target is an approval-gated policy.

**The access request is the unit of elevation.** A request names a **specific** target (or ASG)
and protocol the requester is eligible for, a free-text **reason**, and a requested **duration**
(capped by the eligible policy). This is narrower than "activate the whole policy," which keeps
each grant least-privilege. Its lifecycle:

- `pending` → an approver **approves** (`approved`, sets `expires_at = decided_at + duration`)
  or **denies** (`denied`, with an optional note).
- `approved` is *active* while `now < expires_at`; it becomes `expired` after, or `revoked` if
  an approver ends it early.

**Approver model (v1): any admin.** Approve / deny / revoke are admin-only; auditors may view.
Designated per-target or per-policy approvers, and multi-step chains, are deferred.

**Connect is gated on an active grant.** `issueTicket` continues to run every existing check
(policy match, time window, MFA, host-key/cert pinning, session and idle limits). Additionally,
when the only policy that grants the requested target+protocol is `require_approval`, it
requires an **active, unexpired grant** for that user+target+protocol; absent one it denies with
a new `approval_required` code, and the UI offers "Request access." A grant is *necessary but
not sufficient* — the ordinary policy checks still apply on top of it.

**Expiry blocks new connects (v1).** Grants expire on their own; the connect gate enforces
`now < expires_at` live, and a sweeper (the same pattern as recording retention) transitions
`approved → expired` for state hygiene and to emit the audit event. A session already **live**
when its grant expires is **not** killed in v1 — it ends on its own idle/max-session limits.
Terminating live sessions at grant expiry is the first post-v1 hardening (the session registry
already supports forced termination); operators who want tighter behaviour set the policy's
`max_session_minutes` at or below the typical grant duration.

**Everything is audited.** `access.request.create`, `access.request.approve`,
`access.request.deny`, `access.request.revoke`, and `access.grant.expire` are written to the
existing tamper-evident chain, actor being the requester or the approver; details never contain
secrets. This makes "who asked for what, who approved it, and for how long" a first-class,
verifiable record.

**Surface.**
- Data: `require_approval` on `policies`; a new `access_requests` table (requester, eligible
  policy, target/asg + protocol, reason, requested minutes, status, approver, decided_at,
  decision_note, expires_at, timestamps). Migrations in both dialects.
- API: `POST /access-requests` (eligible user), `GET /access-requests` (own; admin sees all /
  pending), `POST /access-requests/{id}/{approve,deny,revoke}` (admin), `GET /me/access`
  (a user's active grants).
- UI: for an approval-gated target the user's action becomes **Request access** (reason +
  duration) with pending/active/remaining status and a "My access" view; admins get a
  **Pending approvals** queue (approve/deny with a note) and a list of active grants to revoke.

**Explicitly out of scope for v1** (post-v1 PIM): access reviews / recertification; designated,
delegated, or multi-step approvers; email/Slack notifications; SCIM provisioning of eligibility;
automated credential rotation and discovery; and terminating live sessions at grant expiry.

## Consequences

- **Least-standing-privilege becomes possible.** Sensitive targets can be made eligible-only, so
  no one holds standing access; access exists only as a time-boxed, approved, audited grant.
- **Fits the existing model.** `require_approval` defaults off, so the change is backward
  compatible and standing policies are untouched; the connect gate, audit chain, and sweeper
  pattern are reused rather than reinvented.
- **The request lifecycle is fully auditable** on the existing hash-chained log — a concrete
  compliance win (who requested, who approved, scope, duration).
- **Approval is a bottleneck in v1.** With any-admin approval and no notifications, requests can
  wait; mitigated by sane default durations and, later, designated approvers and notifications.
- **A live session outlives its grant in v1.** Because expiry only blocks *new* connects, a
  session started under a grant runs until its own idle/max limits. This is a documented
  limitation; the mitigation (policy `max_session_minutes`) and the fix (terminate-on-expiry)
  are noted above.
- **It extends the v1 timeline.** This is the largest single item in the release and lands as
  several PRs (data model + lifecycle + connect gate → expiry sweeper → UI → docs). That cost is
  accepted as the price of shipping PIM in v1.
- **Roadmap moves.** "Just-in-time access approvals" moves from Phase 4 into the v1.0 scope; the
  remaining Phase 4 PIM items (reviews, delegated approvers, rotation, SCIM) stay deferred.
