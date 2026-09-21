# 0011. Autoscaling health model

Date: 2026-09-20

## Status

Accepted

## Context

Zanskar's distinguishing feature is access to instances in autoscaling groups, where the set of
machines changes without notice. Users need to know which instances they can reach, and when the
one they are on is terminated they need a way to continue on another. Getting this wrong either
shows dead instances as available or interrupts sessions that were fine.

## Decision

**Enrollment.** An admin enrolls an AWS Auto Scaling group by name and region, together with a
cross-account IAM role ARN. Zanskar generates a random ExternalId for the enrollment and the admin
places it in the role's trust policy. The role permissions are limited to:

- `autoscaling:DescribeAutoScalingGroups`, `autoscaling:DescribeAutoScalingInstances`
- `ec2:DescribeInstances`
- `elasticloadbalancing:DescribeTargetHealth`
- optionally `ec2-instance-connect:SendSSHPublicKey`, scoped to instances tagged for the group

Zanskar ships this policy document so that admins can apply it unchanged.

**Credentials.** Instances in a group share a launch template, so a group has one credential
profile, not one per instance. The profile is a normal credential from ADR 0005 and may be an SSH
key from the launch template's key pair, an SSH certificate authority trusted through user data,
EC2 Instance Connect, or a domain account for Windows groups.

**Health.** An instance is `healthy` only when all three signals agree:

1. ASG lifecycle state is `InService`.
2. Load balancer target health, when the group has a target group, is `healthy`. Groups without a
   load balancer skip this check.
3. Zanskar's own TCP probe to the protocol port succeeded within the last polling interval.

Any other combination is `unhealthy`, and an instance no longer returned by the API is `gone`.
The gateway polls at a configurable interval, default thirty seconds, with exponential backoff on
API errors. When the API is unreachable the pool is shown as stale with the age of the data.
EventBridge lifecycle notifications may be added later to shorten detection time; polling remains
the source of truth.

**Failover.** A live session is bound to one instance. When the session's transport drops and the
instance has left the healthy pool, the gateway sends the browser a `target_lost` message with the
current healthy list. The UI shows a modal with one button per healthy instance and an Exit button.
If the list is empty, only Exit is shown. The modal never appears for any other reason: a transport
drop on an instance that is still healthy is reported as an ordinary disconnect, and a user is never
moved between instances automatically.

Switching starts a new session, with its own recording and audit events, using the group's
credential profile. The old session is closed with end reason `target_lost`.

## Consequences

- Users see an accurate pool because three independent signals must agree.
- The role is read-only, so a compromised gateway cannot change infrastructure.
- A single credential profile per group matches how autoscaling actually works and avoids a
  credential rotation problem per instance.
- Polling adds API cost proportional to the number of enrolled groups. The default interval keeps
  this well within free-tier limits for typical deployments.
- Failover is a user action, never automatic, so recordings and audit trails stay unambiguous.
- The same model applies to GCP managed instance groups and Azure scale sets later, behind a
  provider interface with the same three-signal health definition.

## Addendum 2026-09-21: implementation notes

- **Host keys for dynamic instances.** An admin cannot approve a host key for every
  instance an autoscaling group launches. The sync loop therefore verifies each new
  instance's SSH host key against the fingerprints cloud-init prints on the EC2 serial
  console (`ec2:GetConsoleOutput`), which the gateway reads through the cloud API rather
  than over the network path an attacker could sit on. A key confirmed this way is
  recorded with `host_key_source = console`. When the console has no fingerprints
  (custom images without cloud-init), the key is pinned on first contact and recorded as
  `tofu`; the admin UI shows which. A console/observed mismatch is never pinned, the
  instance is marked unhealthy, and `asg.instance.hostkey.mismatch` is audited. A change
  on an already pinned instance is `asg.instance.hostkey.changed` and also unhealthy.
- **EC2 Instance Connect** is a credential type (`ec2_instance_connect`): at connect time
  the gateway generates an ephemeral key, pushes the public half through
  `ec2-instance-connect:SendSSHPublicKey` (valid about a minute) and logs in with the
  private half. Nothing is stored. The permissions policy scopes this to instances tagged
  with the group name.
- **Retiring sessions.** When an instance leaves the healthy pool the registry cancels
  its live sessions with the `target_lost` cause; the browser shows the failover dialog
  only for that reason. Failover is a user action that issues a fresh ticket bound to a
  new session whose `failover_from_session_id` points at the lost one.
- **Scope.** Autoscaling groups support SSH in this release. RDP and WinRM to dynamic
  Windows instances need per-instance certificate pinning, which the console does not
  publish; that is a follow-up.
