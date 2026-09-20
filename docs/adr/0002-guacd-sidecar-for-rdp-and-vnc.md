# 0002. guacd sidecar for RDP and VNC

Date: 2026-09-20

## Status

Accepted

## Context

Windows desktop access requires RDP. Linux desktop access requires RDP through xrdp or VNC.
Implementing these protocols is the largest technical risk in the project.

Alternatives considered:

- **Pure-Go RDP.** The available libraries are incomplete, unmaintained, or both. None handles
  Network Level Authentication, modern codecs, and clipboard reliably. Building our own is a
  multi-year effort.
- **cgo binding to FreeRDP.** Mature protocol support, but it breaks the static binary from
  ADR 0001, pulls a large C dependency into our process, and makes every FreeRDP memory-safety bug
  a gateway compromise.
- **guacd, the Guacamole protocol daemon.** Apache 2.0 licensed, actively maintained by the Apache
  Software Foundation, wraps FreeRDP and libvncserver, and exposes a simple text protocol over a
  socket. Its client library, guacamole-common-js, renders the display in the browser.

## Decision

RDP and VNC sessions are handled by guacd running as a sidecar. Zanskar speaks the Guacamole
protocol to guacd from Go: it performs the handshake, injects the target address and credentials,
and relays the instruction stream between the browser WebSocket and guacd. The browser uses
guacamole-common-js for rendering and input.

SSH remains native Go through `golang.org/x/crypto/ssh` and is never routed through guacd.

Recording of desktop sessions uses the Guacamole protocol stream captured by the gateway, which
can be replayed with the same client library.

## Consequences

- We get working, well-tested RDP and VNC in weeks instead of years.
- guacd receives plaintext desktop credentials, so it must be network-isolated: reachable only
  from the gateway, with no route to the database, object storage, or the internet. The deployment
  documentation and compose file enforce this. Mutual TLS between gateway and guacd is a planned
  hardening item.
- guacd is C code we do not own. We track its advisories and pin its container image digest.
- Desktop sessions need a second process. Single-binary deployments support terminal-only use.
- A future pure-Go RDP implementation can replace guacd behind the same gateway interface without
  changing the API or the frontend.
