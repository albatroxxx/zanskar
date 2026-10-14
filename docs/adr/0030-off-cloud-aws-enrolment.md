# 0030. A gateway outside AWS enrolls autoscaling groups with a certificate

Date: 2026-10-15

## Status

Proposed.

## Context

Enrolling an autoscaling group needs the gateway to assume a read-only role in the
customer's account (ADR 0023). That requires two things: a principal the role's trust
policy can name, and credentials that prove the gateway is that principal.

On AWS compute both come for free — the instance profile or IRSA. Off AWS, today's answer
is `ZANSKAR_AWS_GATEWAY_PRINCIPAL` plus whatever credentials the SDK finds, which in
practice means long-lived access keys in the environment: the exact kind of standing
secret the rest of Zanskar exists to avoid. The console now tells these situations apart
(`platform` on the identity), but the off-cloud path itself is still second-class.

## Decision (proposed)

Support **AWS IAM Roles Anywhere** as the first-class off-cloud path: the gateway proves
itself with an X.509 client certificate instead of stored keys.

- The operator registers a **trust anchor** (their private CA, or one Zanskar generates
  and shows once) in IAM Roles Anywhere, plus a **profile** naming the role to vend.
- The gateway holds a certificate and private key under that CA; the key is sealed with
  the keyring like every other secret, and never leaves the box.
- At sync time the gateway exchanges a signed request for **temporary** credentials
  (`rolesanywhere:CreateSession`), then assumes the per-group read-only role exactly as
  on-cloud gateways do. No standing AWS keys anywhere.
- The console's enroll flow gains a third identity source beside instance-profile and
  environment: *certificate (Roles Anywhere)*, with the same paste-ready setup script
  treatment ADR 0023 gives the role itself (trust anchor ARN, profile ARN, certificate).
- Rotation reuses the credential-rotation machinery (ADR 0022's prepare/retire shape).

Other clouds follow the same shape later — certificate- or token-based workload identity
federation (GCP WIF, Azure federated credentials) — behind the same `platform` detection;
nothing in this ADR assumes AWS is the only provider forever.

## Consequences

- An off-cloud gateway gets autoscaling without static cloud keys; the threat model gains
  one sealed private key instead of a reusable secret that works from anywhere.
- New moving parts: trust-anchor/profile setup on the customer side, a certificate
  lifecycle on ours, and the Roles Anywhere signing flow (SigV4 with the certificate) in
  `internal/cloud`.
- Enrolment docs split by where the gateway runs; the console already knows which page to
  show thanks to `platform`.

## Alternatives considered

- **Static access keys in the environment** — works today, rejected as the recommended
  path: standing secrets, no attestation, contradicts the product's own posture.
- **Running a tiny broker on AWS that the gateway calls** — moves the problem (the broker
  needs authenticating) and adds infrastructure.
