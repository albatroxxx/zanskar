# 0012. RDP and VNC trust through guacd

Date: 2026-09-20

## Status

Accepted

## Context

For SSH, Zanskar pins the host key captured at probe time and refuses to connect to anything
else (ADR 0011 and the threat model). RDP and VNC go through guacd (ADR 0002), which owns the
TLS handshake, so Zanskar cannot verify the certificate itself.

guacd 1.6 added two RDP parameters: `cert-tofu`, which trusts the first certificate seen, and
`cert-fingerprints`, a list of SHA-256 fingerprints to accept. Older guacd only offered
`ignore-cert`.

## Decision

- Zanskar requires guacd 1.6 or newer. The compose file pins `guacamole/guacd:1.6.0`.
- The probe captures the RDP server certificate's SHA-256 fingerprint and stores it on the
  target as `tls_fingerprint`. An RDP connect is refused until a fingerprint exists.
- Every RDP connection passes `ignore-cert=false` and `cert-fingerprints=<pinned>`. guacd
  refuses any other certificate. `cert-tofu` is never set.
- When a probe sees a different certificate after one was pinned, the target keeps the old
  fingerprint and the change is audited, mirroring the SSH `changed` state. An admin re-probes
  and confirms to accept the new certificate.
- VNC has no certificate in the base protocol. Plain VNC is allowed but its traffic between
  guacd and the target is unencrypted; the admin UI shows a warning on VNC targets, and a
  policy can exclude the protocol.
- Desktop sessions disable audio, drive redirection and printing by default. Clipboard and file
  transfer follow the policy flags, enforced in the Zanskar bridge by dropping the relevant
  instructions in both directions rather than trusting guacd parameters alone.

## Consequences

- No trust-on-first-use at connect time for RDP; trust is established only by an admin action.
- RDP to a host that rotates its self-signed certificate needs a re-probe. That is the right
  friction: a silent change is exactly the case this defends against.
- guacd upgrades are a security dependency and tracked by Dependabot on the compose file.

## Addendum 2026-09-21: WinRM

WinRM follows the same rule. The probe captures the HTTPS listener's leaf certificate
separately from the RDP one (a Windows host presents different certificates on the two
listeners) and stores it as `winrm_tls_fingerprint`. A WinRM connect is refused until a
fingerprint exists, and the gateway's own TLS transport accepts exactly that certificate:
the CA and hostname checks are replaced by a SHA-256 match, which is what self-signed
listener certificates need. A mismatch at connect time is refused and audited as
`target.tls.mismatch`. WinRM over plain HTTP (5985) is refused outright: the Go client has
no WS-Management message encryption, so command output would cross the network in clear.
