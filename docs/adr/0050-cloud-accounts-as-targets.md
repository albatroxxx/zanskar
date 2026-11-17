# 0050. Cloud accounts as targets: temporary elevated access to AWS, approved, bounded, on the record

Date: 2026-11-16

## Status

Accepted 2026-11-16: the owner took every recommendation below ("use your recommendation") and
asked for the build to start: phases B and C after ADR 0049, and phase D (Identity Center mode) when
an organization asks for it, as decision 6 recommends. Needs [ADR 0049](0049-approvers.md) (approvers) first. Follows the shape of
[ADR 0045](0045-kubernetes-clusters-as-targets.md) and [ADR 0048](0048-fabric.md): a new kind of
target, derived, with a platform column, reached through a role the gateway assumes as autoscaling
groups (ADR 0023) and EKS clusters are.

## Context

The owner, 2026-11-16: a feature "inspired by AWS TEAM for access management for AWS", to "provide
access to cloud environment" the way TEAM gives temporary elevated access.

What TEAM is (its documentation, read 2026-11-16): an open-source application in the IAM Identity
Center delegated-administrator account. An *eligibility policy* says which Identity Center users or
groups may request which permission sets in which accounts or organizational units, for at most how
long, and whether approval is needed. A request names an account, a permission set, a start time, a
duration, a justification and a ticket number. When approved and due, a Step Functions workflow
calls `CreateAccountAssignment` for the person's own Identity Center user; when the duration ends or
someone revokes, `DeleteAccountAssignment`. The person signs in to the AWS access portal as
themselves. Session activity is read from CloudTrail Lake and shown per request. Its limits, by its
own account: an AWS session started before the window closes runs on until the permission set's
session duration ends (TEAM recommends one hour); it needs an organization and Identity Center; it
holds the power to assign any permission set it is allowed to, in the delegated-admin account.

What Zanskar has: the request, the grant and the record (ADR 0018, with approvers from ADR 0049);
a target model where a kind is derived from the row (`internal/target/target.go:737-757`), a grant
names a kind, targets or tags, protocols and conditions (ADR 0036), and a session without a socket
exists for Kubernetes (`internal/connect/kube.go`): started at Connect, a bearer token the gateway
alone can check, one recording line per thing done, ended by its clocks, a terminate or a policy
change. The AWS plumbing exists: the gateway's own principal is discovered or set
(`internal/cloud/identity.go`), a role in another account is assumed with an ExternalId Zanskar
mints (`internal/cloud/aws.go:84-124`), the trust and permissions policies are printed for pasting
(`internal/asg/asg.go:16-62`, `internal/cloud/eks.go:241-281`), and the EKS adapter mints a
short token per session and reuses it for twelve of its fifteen minutes (`internal/cloud/eks.go`).

What AWS allows (its documentation, read 2026-11-16):

- A role assumed by an application running on an EC2 instance role is not role chaining, so
  `DurationSeconds` may run to the role's maximum session duration (up to 12 hours). A role
  assumed from credentials that are themselves an assumed role (IRSA on Kubernetes, a chained
  role) is chaining: one hour, and the console `SessionDuration` parameter is refused.
- A console sign-in URL is made at the federation endpoint from the temporary credentials
  (`getSigninToken`, then `login`); it is valid for 15 minutes, the console session for the
  credentials' duration or the `SessionDuration` asked for, below the role's maximum. AWS: "you
  should treat the URL as a secret"; the endpoint accepts POST.
- A role session cannot be ended early except by attaching a deny policy to the role conditioned on
  `aws:TokenIssueTime`, which needs `iam:PutRolePolicy` on the role and affects every session of
  it. Roles made by Identity Center permission sets cannot be edited at all.
- `cloudtrail:LookupEvents` returns management events of the last 90 days by one attribute
  (`Username` among them), up to 15 minutes late, at two calls a second per account and region.
- `CreateAccountAssignment` is asynchronous: it returns a request id to poll with
  `DescribeAccountAssignmentCreationStatus`; the principal is an Identity Center user or group id.

## Decision

**Posture first.** The gateway becomes a principal that can act inside enrolled AWS accounts with
the enrolled roles' permissions, on a person's behalf: the widest trust Zanskar has taken, wider
than reaching a host or impersonating in a cluster. It is bounded as autoscaling and EKS bound
theirs: each role's trust policy names this gateway's principal and an ExternalId Zanskar minted,
so no other principal can use the enrolment; enrolment is an administrator's audited act; the
gateway holds no long-lived secret for any account; every credential it mints carries the person's
username as `SourceIdentity` and a session name that is Zanskar's session id, so CloudTrail in the
account names the person and the session. The release notes say this first, in bold.

**1. A cloud account's role is a target.** Kind `cloud`, derived as the others are, from
`cloud_role_arn` being set. One target is one role in one account ("prod · AdministratorAccess"):
`cloud_platform` (`aws`; the column is for GCP and Azure later, as `kube_platform` was for EKS),
`cloud_account_id`, `cloud_account_alias`, `cloud_role_arn`, `cloud_external_id`,
`cloud_max_minutes` (default 60, at most 720, never above the role's own maximum, which Test
reads), `cloud_region` (where the console opens). Tags carry the grouping (`account=prod`,
`role=readonly`). The console's list groups roles under their account. A role-mode target has no credential slot (phase D's
Identity Center mode puts its steward credential on the slot): the trust is the role's trust
policy, as for an autoscaling group, and the target's **Setup** prints it with the gateway's
principal and the ExternalId condition, allowing `sts:AssumeRole`, `sts:SetSourceIdentity` and
`sts:TagSession` (the autoscaling policy plus the two actions the mint below needs; without them
STS refuses a source identity or a tag), plus the one-line CLI and the CloudFormation snippet
(`asg.RoleCLI`'s pattern). **Test** assumes the role for the target's `cloud_max_minutes` with the
source identity and tags set, calls `GetCallerIdentity` and shows the assumed ARN; a refusal names
its cause (the trust policy, the ExternalId, a duration above the role's maximum, which the admin
then lowers) so that `iam:GetRole` is never asked for; and it says whether `LookupEvents` is
allowed. The source identity is the username where it fits AWS's rule (2 to 64 characters of
letters, digits and `_+=,.@-`); a character outside that set becomes `_`, longer is cut at 64, and
a value beginning `aws:` is prefixed `zanskar-`. The audit event carries the full username, and the
session name `zanskar-<session id>` is the join in every case.

**2. One protocol, `cloud`.** Added to the closed list and to the four CHECK constraints
(`target_credentials`, `access_sessions`, `access_requests`, plus `credentials.type` if phase D
adds its credential type), rebuilt on SQLite as 0056 did. The grant kind is `cloud`: targets or
tags, every ordinary condition (standing or approval with approvers, authenticator, time windows,
idle and maximum, retention), and two switches of its own, **Console** and **Command line**, both
on by default, as a Kubernetes grant has cluster scope and port-forward. A session's duration is
the grant's maximum session, capped by the target's `cloud_max_minutes`; where grants overlap, the
strictest, as always.

**3. The session is the AWS session, started by Zanskar.** Connect with protocol `cloud` (a
standing grant, or an active approved grant, through the gate as any connect) does what `startKube`
does: admits, registers a session, opens a recording, and mints a bearer token (`zaws_…`, only its
hash stored) that is the person's handle on the session. Then:

- **Command line.** The portal shows one profile stanza to paste into `~/.aws/config`:
  `credential_process` running `curl` against `GET /cloud/<session>/credentials` with the bearer.
  The gateway answers with AWS's `credential_process` JSON from a **fifteen-minute** `AssumeRole`
  it re-mints while the session lives and reuses for twelve of its minutes, the EKS token's
  pattern. No client is installed; the AWS CLI and SDKs already speak this. A terminate stops the
  endpoint, and the last credentials die within fifteen minutes.
- **Console.** *Open console* asks `POST /cloud/<session>/console`; the gateway assumes the role for
  the session's remaining minutes (the one mint that lives long), exchanges the credentials at the
  federation endpoint for a sign-in token, and answers with the `login` parameters, which the portal
  POSTs into a new tab (ADR 0038: sessions open in their own tab). The URL is never built as a GET
  the browser would keep in its history, and never shown. It may be asked for again while the
  session lives; each issue is a recording line and an audit event.
- **No idle.** The gateway sees no request stream: CLI calls and console clicks go to AWS. The
  session ends at its duration (`max_duration`), on terminate, on a policy change that no longer
  admits it or changes its switches (`policy_revoked`), when the target's account, role or
  ExternalId is edited, or when the person ends their grant (ADR 0049). The idle setting of the
  grant does not apply, and the editor says so for a cloud grant.
- **Terminate is honest.** After a terminate the command line stops within fifteen minutes; a
  console session already open runs to its end, which AWS gives no way to cut short without IAM
  writes on the role. The console shows the two times when it ends such a session, the recording
  says them, and the guide says so, as TEAM's documentation does. The default of 60 minutes keeps
  the exposure to what TEAM recommends.

**4. On the record.** `session.start` with protocol `cloud`, the account, the role, which switches
were on; the recording (`.cast`, as the Kubernetes one) holds one line per thing the gateway did:
the session started as `arn:aws:sts::<account>:assumed-role/<role>/zanskar-<session>`, command-line
credentials issued until *hh:mm*, console sign-in issued, terminated with both end times. **Phase C**
adds what the person did: after the session, and on demand during it, the gateway reads
`LookupEvents` with `Username` = the session name in the account, through the enrolled role under
its own session name (`zanskar-gateway-audit`), and appends the events as lines (time, event
source, event name, read-only or not, the resource names), with the 15-minute lateness said. The
Sessions page gains *Activity* for a cloud session; the auditor reads it as any recording.

**5. Identity Center mode, phase D.** For organizations on Identity Center, TEAM's mechanism as a
second mode of the same kind: a credential type `aws_identity_center` (region, a steward role in
the delegated-administrator account trusting this gateway with an ExternalId, the instance ARN and
the identity store id); a target of platform `aws` whose `cloud_permission_set_arn` is set instead
of a role ARN, the credential on its slot. A session looks the person up in the identity store by
username, then email (`GetUserId`), calls `CreateAccountAssignment` for that user and polls the
status until it succeeds (seconds to a minute), and shows the access portal's start URL; it ends
with `DeleteAccountAssignment`. The person acts as themselves, which CloudTrail names without any
help; Zanskar never holds the elevated credentials. Its limit is TEAM's: an AWS session already
open runs to the permission set's session duration, and Zanskar says so. Whether the steward role's
policy can be scoped to the enrolled permission sets and accounts by resource ARN is to be
confirmed against the Service Authorization Reference when the phase starts; the plan assumes it
can and the Setup prints the scoped statement. Not for an account without an organization
instance; the Setup says so when `ListInstances` finds none.

**6. Platforms later, the shape now.** Kind, grant, session, portal tab and recording know an
*account*, a *role*, *console* and *command line*; nothing in them says AWS. GCP (a project and a
role, granted for a window through Privileged Access Manager or a time-conditioned binding) and
Azure (a subscription or resource group and a role, through Privileged Identity Management or a
time-bound assignment) are platforms of the same kind when asked for, as GKE and AKS were. The
console shows the AWS platform alone until then: no placeholder tiles.

## Surface, the cross-cutting list

A kind is copied in these places, each to touch (the list ADR 0048 promised):
`Target.Kind()` and `kindClauses`/`Inventory` (`internal/target`), `protocol.Kinds` and
`kindProtocols`, the CLI's kind column and `target show`, `connect.reachableTarget`, the console's
`policyModel.ts`, `TargetForm.tsx` (a *Cloud* tab with the fields above) and the portal's
`Targets.tsx` (a *Cloud* tab: account, role, **Open console**, **Command line**, with the request
flow of an approval-gated target as today); the protocol CHECKs in both engines (migration 0059);
grant kind and switches in `internal/policy` and the editor; `configio` carriers and defaults; the
Terraform provider's target and grant schemas; OpenAPI's kind, platform and protocol enums and the
new routes; the admin overview's `cloud_accounts` count and the dashboard tile; `format.ts` labels
(protocol *Cloud*, platform *AWS*); the lifecycle labels (no new state: a cloud session is a
session); the guide's *Cloud accounts* section and the 2.x release note's posture line.

New code: `internal/cloud/sts.go` (the per-session mint with `SourceIdentity` and tags, the
federation exchange, the sign-in form), `internal/connect/cloud.go` (`startCloud`, the credentials
and console routes, the clocks), `internal/target/cloud.go` (validation, Setup, Test),
`internal/cloud/cloudtrail.go` (phase C), `internal/cloud/identitycenter.go` (phase D). The AWS SDK
modules `sts` (present), `cloudtrail` (C), `ssoadmin` and `identitystore` (D).

## The plan

For one engineer, with tests. ADR 0049 (two weeks) comes first.

**Phase B — AWS through a role (about three weeks).** The kind and its migration; Setup and Test;
the grant kind and switches; `startCloud` with the two mints, the credentials endpoint and the
console form; the portal tab and dialogs; recording lines and audit events; configio, Terraform,
OpenAPI, CLI; the guide. Its first engineering step is a measurement, not a feature: **mint once
from the live gateway's instance profile with `DurationSeconds` above one hour and exchange it at
the federation endpoint**. AWS's page both exempts EC2 instance roles from chaining and says the
duration "must" come from an IAM user for the federation call to succeed; which holds decides
whether a console session may be longer than an hour. If it fails, the console mint is one hour
and the grant's longer duration applies to the command line alone; the ADR is amended with the
measurement. A gateway on Kubernetes (IRSA) is chaining: one hour, said in the Setup.

**Phase C — activity from CloudTrail (about one week).** The `LookupEvents` reader, the Activity
view, the `cloudtrail:LookupEvents` statement in Setup and the Test line.

**Phase D — Identity Center mode (about one and a half weeks).** The credential type, the steward
role's Setup, the permission-set target, the assignment session, the scoping confirmation.

**Later, when asked:** GCP and Azure platforms; a per-session console revoke through a steward role
holding `iam:PutRolePolicy` on the enrolled role (a posture widening of its own: the gateway could
then rewrite the role's permissions, and the deny hits every session of the role), if the owner
wants console terminates to bite and accepts that.

## Consequences

- People request and receive an AWS role the way they request a host: the same policy, the same
  approver (ADR 0049), the same record, and nothing in the account but a role trusting this
  gateway. Where TEAM needs an organization, Identity Center and a deployment of its own, phase B
  needs one role per account.
- Attribution is by `SourceIdentity` and session name, both in CloudTrail, rather than by the
  person's own cloud identity; phase D gives the latter where Identity Center exists.
- A cloud session is the first with no idle clock and the first the gateway cannot end at will
  in every part; both are stated where the person sees them.
- The gateway's role on AWS grows from *describe* and *send a key* to *assume*; the Setup pages and
  the release note say what each enrolment adds.

## Decisions owed by the owner

Each with one recommendation and its reason.

1. **Which mechanism first.** Recommended: the role (phase B). It reuses the trust pattern three
   features already use, works on an account without an organization, and can be tested on the
   owner's account today. Identity Center (phase D) follows for organizations that have it.
2. **Console sessions and terminate.** Recommended: accept AWS's limit, default 60 minutes, say the
   end times plainly. Alternative: the steward-role revoke, a posture widening to decide on its
   own.
3. **Name and address.** Recommended: the section reads *Cloud accounts*, at `/admin/cloud`, the
   portal tab *Cloud*; names say what they hold (the Fabric lesson, ADR 0048 decision 7).
4. **Durations.** Recommended: a target defaults to 60 minutes and allows up to 720, the grant's
   maximum session is the session's length within that. TEAM allows windows up to a year because
   its window is not a session; Zanskar's is.
5. **Activity reading.** Recommended: through the enrolled role, under its own session name, with
   `cloudtrail:LookupEvents` in the Setup. Alternative: a separate read-only audit role per account,
   one more thing to enrol.
6. **Phase D in the first release?** Recommended: no; ship B, then C, and D when an organization
   asks or the owner's accounts move to Identity Center.
7. **GCP and Azure.** Recommended: the column and the shape now, the adapters when a person needs
   them, as for GKE and AKS.
