# 0024. Windows sessions on autoscaling instances, pinned per instance

Date: 2026-09-30

## Status

Accepted. Closes the scope note in 0011 (autoscaling health model), which limited
autoscaling groups to SSH, and follows 0012 (certificate pinning for RDP and WinRM).

## Context

0011 left RDP and WinRM to autoscaling instances out of scope for one reason: pinning. A
static target is probed once by an administrator, who looks at the fingerprint and trusts
it. An autoscaling instance has no such moment. It appears when the group scales out and
is gone an hour later, so nobody is there to approve its certificate, and the certificate
is usually one the instance generated for itself at first boot.

Enrolment did not enforce the limit, only sessions did. A Windows group could be enrolled
with RDP and WinRM capabilities, would sync, and would report healthy instances, yet every
connection was refused with `protocol_unavailable`. That is the worst arrangement: the
product looks like it supports something it does not, and the person finds out at the
moment they need a session.

Three options were considered.

- **Reuse the group's fingerprint.** One pinned certificate for the whole group, checked
  against every instance. This is what most gateways do, and it only works when the
  certificate comes from a real internal authority baked into the image. Self-signed
  per-instance certificates, which is what Windows produces by default, would all fail.
- **Skip pinning for groups.** Honest about the limits, and quietly worse than what a
  plain RDP client offers. Rejected: an unauthenticated listener on a cloud network is
  exactly the thing this product exists to prevent.
- **Pin per instance, first sighting wins.** The sync loop already probes every instance
  on every poll, and the probe already captures the RDP and WinRM certificates.

## Decision

Each autoscaling instance carries its own `tls_fingerprint` and `winrm_tls_fingerprint`,
captured by the sync loop the first time the instance answers, and kept for the life of
that instance. A later poll that sees a different certificate on the same instance does
not re-pin: the instance is marked unhealthy, the change is audited as
`asg.instance.certificate.changed`, and its live sessions end through the usual retirement
path. Sessions are then allowed for any protocol the group declares, and the session
handlers for RDP and WinRM resolve their endpoint the way the SSH one already did, so a
group instance and a static host follow the same policy, pinning and recording code.

Trust on first sight is weaker than an administrator reading a fingerprint, and we say so
rather than dressing it up. It is the same compromise 0011 already accepted for SSH host
keys when the cloud publishes no console output, and it is strictly better than the
alternative people reach for otherwise, which is disabling certificate checks.

Database access stays out: a database is an endpoint with a credential and a TLS mode, not
a machine that scales, so it is enrolled as its own target.

## Consequences

- A Windows autoscaling group is usable end to end: enrol, sync, and open a desktop or a
  PowerShell console on any healthy instance.
- An instance whose certificate is replaced under us becomes unusable until it is replaced
  by the group, which is the behaviour we want and will occasionally surprise someone who
  renews a certificate in place.
- The WinRM credential for a group must be a local administrator on the instances, because
  Zanskar opens a WinRS shell and WinRM's RootSDDL grants that to administrators only.
  Membership of Remote Management Users is not enough. The gateway now says this in the
  refusal instead of reporting a generic connection failure.
- Windows instances are expected to be built from an image that already has the HTTPS
  WinRM listener and the RDP certificate, since there is no moment to configure them by
  hand. The user manual says how.
