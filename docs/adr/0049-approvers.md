# 0049. Approvers: a fourth role, and a grant that names who decides

Date: 2026-11-16

## Status

Accepted 2026-11-16: the owner took every recommendation below ("use your recommendation") and
asked for the build to start. Amends [ADR 0006](0006-roles-admin-auditor-user.md) (three roles) and
[ADR 0018](0018-just-in-time-access-approvals.md) (approver model v1: any admin). Written with
[ADR 0050](0050-cloud-accounts-as-targets.md), which needs it: elevated access to a cloud account
is the request that most wants a named approver.

## Context

The owner, 2026-11-16: build temporary elevated access to cloud environments the way AWS's
*Temporary Elevated Access Management* (TEAM) does it, and "break the roles from 3 to 4 by adding
Approvers as a role".

TEAM has four personas: a requester asks, an approver decides, an auditor reads, an admin
configures. Its *approval policy* names, per account or organizational unit, the Identity Center
groups whose members may approve; a request for an account that has no approval policy, or whose
approver groups are empty, is blocked; an individual never approves their own request; using the
same group for eligibility and approval is "peer approval". A pending request expires after a
configured time (three hours by default); the requester may cancel it while pending, and the
requester or an approver may revoke access that is active.

Zanskar has the request, the grant and the record (ADR 0018, 1.0.0): a policy grant whose access
is *approval* makes people eligible; a request names one target and protocol, a reason and a
duration; an approval becomes a grant that ends on its own, ends its sessions when revoked, and
every step is an event in the hash chain. What it lacks is the approver. Today:

- `approve`, `deny` and `revoke` and the queue are admin-only
  (`internal/access/handlers.go:57-61`); ADR 0018 deferred "designated per-target or per-policy
  approvers, and multi-step chains", and the roadmap lists "delegated/multi-step approvers" under
  Phase 4.
- Nothing stops an admin approving their own request, by decision (2026-10-04): an admin can write
  a policy, so the approval step is a check on users, not on admins, and the record is what
  protects the estate. ADR 0018 says designated approvers "are the place to require a second
  person".
- A pending request never lapses and cannot be withdrawn (`internal/access/lifecycle.go`).
- Notifications (ADR 0039) go to channels, a signed webhook or an email list, not to people; the
  `access_requested` message links to `/admin/approvals?request=<id>`.
- The three roles are `admin`, `auditor`, `user` (`internal/user/user.go:15-25`, the CHECK in
  migration 0001). A synced user's roles come from the provider's `default_roles` alone; a group
  mapping maps an external group to a Zanskar group, never to a role (`internal/idp/idp.go:46-56`).

## Decision

**1. A fourth role, `approver`.** It lets an account open the approvals view and decide the
requests it is named for. It grants nothing else: an account holding only `approver` cannot see
targets or connect (`CanConnect` stays `user || admin`), and cannot read recordings or the audit
log. Granting it is an audit event, as granting `admin` or `auditor` is; it counts as privileged in the users list. An admin is admitted wherever an approver is, each
route listing both roles, as admin and auditor share the review routes today.

**2. A grant names its approvers.** An approval grant (ADR 0036) gains `approvers`: zero to 32 rows
of `{kind: group | user, id}`, the same shape as a policy's subjects. A user approver must hold the
approver role (or be an admin), else `422 not_an_approver`; a group is not inspected when saved,
and a member without the role is refused at the route, as a review-only subject is today. Where a
grant selects targets by tag (`account=prod`), its approvers are TEAM's per-account approval policy;
where it names targets, they are per-target approvers. The approvers live on the grant because every
condition does (ADR 0036: "no inheritance and no override"), and the editor already draws grants.

**3. Role and designation are two things.** The role without a designation approves nothing: the
view is empty. A designation without the role decides nothing: the route refuses (`403
forbidden`). Both are needed, and each alone is harmless.

**4. Who decides.** A request's approvers are the union of the `approvers` of the approval grants
that make the requester eligible for that target and protocol, computed when the queue is listed
and again when a decision is made (ADR 0018 already re-decides eligibility at that moment, finding
SEC-2). Then:

- **Nobody named: as today.** Any admin approves, denies or revokes. Nothing shipped changes until
  someone names an approver.
- **Someone named: the named decide.** They approve and deny; an admin sees the request in the
  admin queue with its approvers listed, and does not approve or deny it. An admin may **revoke**
  any grant; so may a named approver, for the grants in their scope. A designation an administrator
  can override would be decoration; and a policy edit is a loud, audited change while an approval
  is a quiet one. This is TEAM's shape: an administrator who should decide joins the approvers.
- **Never one's own.** A named approver cannot approve, deny or revoke their own request (`403
  own_request`). A request whose approver set, minus the requester, is empty is refused when
  created (`422 no_approver`, naming the grant), as TEAM blocks a request nobody can approve.
- **An admin's own request** stays as decided on 2026-10-04 where nobody is named; where someone is
  named, the admin's request waits for them like anyone's.

**5. Where approvers work.** A fourth route tree, `/approvals`, guarded by the approver role: one
page with the pending requests in the person's scope (approve with minutes and a note, deny with a
note; the step-up code when *Approving asks for a code* is on), the grants they may revoke, and the
history of what they decided. The access portal shows an **Approvals** item with the pending count
to anyone holding the role; an account holding only `approver` lands there. The admin portal keeps
its own Approvals page over every request, and its pending table gains an *Approvers* column.

**6. Approvers are told.** When a request's approvers are named, each with an email address on file
is sent the `access_requested` message directly, through the one email server (Settings ›
Notifications), with the link to `/approvals?request=<id>`; an approver without an address is not
written to and sees the request in the view. Channels keep receiving every `access_requested` and
`access_decided` as today; nothing is taken from them. The decision message to the requester is
unchanged.

**7. The role at scale.** A provider that owns the person (ADR 0035) gains **Approver groups**: the
external groups (OIDC claim values, SCIM groups, LDAP group DNs, as `GroupMapping` keys are) whose
members hold the approver role, granted and withdrawn on every sync and sign-in as mapped group
membership is. Approver groups apply where the provider hands over group membership, which is at
sign-in (an OIDC provider's groups claim, which the setting therefore requires; an LDAP user's
`memberOf`); the directory sync and SCIM carry no groups, so a SCIM-only provider's approvers
take the role by hand or through an LDAP or OIDC sign-in. A withdrawal that would leave the account
with no role leaves it `user` instead (the owner's call, 2026-11-17), so a person the provider still
signs in still opens the portal. Local accounts take the role from the
user form. Admin and auditor stay as they are: nobody asked for them from groups.

**8. Two small moves the requester may get, if the owner wants them** (decision 7 below): to
**cancel** a pending request (`pending → cancelled`, `access.request.cancel`) and to **end** their
own active grant (`approved → revoked` by the requester, the event naming them; their sessions end
as a revoke ends them). Both exist in TEAM and need no setting; neither was asked for, so neither is
decided here.

## What this does not decide

TEAM's other request settings are global settings, and the recorded rule is to ask before adding
one. They are listed for the owner below, not built by this ADR: a pending request that lapses
after a time (`pending → lapsed`), a required ticket number, a required reason, a required decision
note, a scheduled start. Multi-step chains stay out, as ADR 0018 left them.

## Surface

- `internal/user`: the constant, `ValidRole`, `NormalizeRoles`; migration 0058 rebuilds the role
  CHECK in both engines (the SQLite rebuild of 0056's shape).
- `internal/policy`: `approvers` on a grant, validation; `Evaluate` returns the approver set
  beside `RequireApproval`.
- `internal/access`: `RequireRole(admin, approver)` on the queue and decision routes with the scope
  check in the handler (the test: an approver outside scope gets 403; a named approver deciding
  their own gets 403; a request nobody else can approve gets 422); `cancel` and the requester's revoke if decided; `scope=mine` on the list; the lifecycle declaration, the label table, the OpenAPI enum,
  `docs/lifecycles.md` and `cmd/zanskar/lifecycles_test.go` for `cancelled`, if decided.
- `internal/notify`: per-recipient email for `access_requested`; the approver link.
- `internal/idp`: `approver_groups` on a provider; the sync.
- `internal/audit/actions.go`: `access.request.cancel`; `user.roles.update` already records the role
  grant, as it does for admin and auditor.
- Console: `Role` type, `RolePicker`, `roles.ts`, `homeFor`, `Guard`, `Shell`; the `/approvals`
  tree reusing the admin Approvals components; the grant editor's approvers picker (shown when
  access is *approval*); the admin queue's Approvers column; *Cancel* and *End* on My access.
- OpenAPI prose and tags for the role; `users --role approver` in the console CLI; the
  configuration file and the Terraform provider carry a grant's `approvers`.
- The guide: Policies (approvers), a new *Approving* section, Identity providers (approver groups).

## The plan

For one engineer, with tests. **About two weeks**: the role and its migration (two days), the
grant field and the decision rules (three days), the approvals tree and the portal item (three
days), per-recipient email and approver groups (two days), docs and the break-it pass (two days);
cancel and end, if decided, add a day. It comes before ADR 0050's first phase, which needs it.

## Consequences

- Separation of duties gains the thing ADR 0006 could not give: a decision made by someone who is
  not an administrator and cannot write a policy, on the record.
- Existing deployments feel nothing until a grant names an approver. A small team of admins keeps
  approving as it does.
- Eligibility and approval scope are recomputed from the policies as they stand, so a grant edited
  while a request waits changes who may decide it, as it already changes whether it may be granted.
- A fourth role is a fourth line in every place roles are listed; the surface above is the list.

## Decisions owed by the owner

Each with one recommendation and its reason.

1. **Admins where approvers are named.** Recommended: the named decide; admins revoke and see.
   Alternative: admins also approve and deny. The recommendation gives the designation teeth.
2. **An admin's own request where nobody is named.** Recommended: keep the 2026-10-04 decision.
   Reversing it adds friction and no control, as ADR 0018 argues.
3. **Where approvers work.** Recommended: a `/approvals` tree plus an item in the access portal.
   Alternative: inside the admin portal only, which would make every approver an admin.
4. **The role at scale.** Recommended: approver groups on the provider. Alternative: by hand on
   each synced user, which does not scale and fights ADR 0035.
5. **TEAM's request settings**, each a global setting: a pending request lapses after N hours
   (TEAM: 3; recommended if wanted: 24, with notifications a day is a working day across time
   zones), a ticket number required, a reason required, a decision note required. Recommended: none now.
6. **Scheduled start.** TEAM has it; it adds a state (`scheduled`), a start timer and a second
   clock on every grant. Recommended: defer until asked for by a person who needs it.
7. **Requester cancel and end** (point 8). Recommended: yes to both; one event each, no setting, a
   day of work, and a person who asked by mistake or finished early need not wait for an approver.
