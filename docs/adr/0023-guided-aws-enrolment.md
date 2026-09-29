# 0023. Guided AWS enrolment: the gateway knows its own identity, and roles only

Date: 2026-09-29

## Status

Accepted. Extends 0011 (autoscaling health model), which introduced the cross-account role
with an ExternalId.

## Context

Enrolling an autoscaling group needs a role in the customer's account whose trust policy
names the gateway's own principal and carries the ExternalId Zanskar generated. Until now the
gateway only knew its principal from `ZANSKAR_AWS_GATEWAY_PRINCIPAL`; when that was unset the
console showed a trust policy with `<GATEWAY-ACCOUNT-ID>` placeholders that looked finished
and was not (manual QA item 10, folded into item 11). The ExternalId was minted only when
the group was saved, so the customer could not create the role first; the role ARN was
required before anything could be checked; and nothing verified the role before the sync
loop failed on it. The terraform test environment already derives the principal from the
instance metadata service and its comment records the one trap: a trust policy must name
the **role** ARN, not the instance-profile ARN and not the assumed-role session ARN STS
reports.

## Decision

**The gateway detects its own principal.** At start, and on demand from the console, it asks
STS `GetCallerIdentity` through the SDK's default chain (instance profile, IRSA, environment,
shared profile) and converts `arn:aws:sts::ACCT:assumed-role/ROLE/session` to
`arn:aws:iam::ACCT:role/ROLE`. `ZANSKAR_AWS_GATEWAY_PRINCIPAL` remains as an explicit override
that wins over detection, for a gateway outside AWS or one that should present a different
principal. The source of the principal (environment, detected, none) is always shown.

**Never a placeholder.** When no principal is known, the trust policy, the CLI script and
the CloudFormation template are withheld and the console says what to do; the permissions
policy, which does not depend on the principal, is still shown.

**Enrolment is guided and checked before it is saved.** The console mints the ExternalId in
an IAM preview before the group exists, renders the trust policy with the real principal,
the permissions policy, a paste-ready AWS CLI script that creates the role, and the same
role as a CloudFormation template. The customer creates the role, pastes its ARN, and
**tests** it: the gateway assumes the role with the ExternalId (`GetCallerIdentity` forces
the assume, so a wrong principal or ExternalId fails there) and describes the group, and the
answer names the failing stage: trust policy, permissions, or no such group in that region.
The group is then created with the previewed ExternalId. A saved group can be tested the
same way. Tests are audited as `asg.test`.

**Roles only.** Zanskar will not store AWS access keys. A gateway that is not on AWS and has
no role to run as sets the override and uses whatever the SDK's default chain provides; the
product does not add a vault for long-lived cloud keys.

## Consequences

- The `asg.AdminHandler` takes an identity resolver and a provider factory instead of a
  principal string; the provider interface gains `Check`. Routes:
  `POST /autoscaling-groups/iam-preview`, `POST /autoscaling-groups/test`,
  `POST /autoscaling-groups/{id}/test`, `GET /admin/aws/identity`,
  `POST /admin/aws/identity/refresh`; `external_id` is accepted on create and must be one
  Zanskar minted.
- The trust policy is only half of an assume-role handshake: the gateway's own role must
  also be permitted `sts:AssumeRole` on the customer role ARN. The deploy guide says so and
  the `assume`-stage hint mentions it, because both failures look the same from STS.
- Detection is bounded (five seconds) and cached; off AWS it fails fast and the console
  shows source `none` with the reason. It never blocks start-up.
- 0011 listed `autoscaling:DescribeAutoScalingInstances` among the permissions; the gateway
  never needed it and the shipped policy does not grant it. The permissions policy in the
  console is the reference.
- The terraform test environment's user-data no longer has to compute the principal for the
  gateway; it may keep doing so as the override.
