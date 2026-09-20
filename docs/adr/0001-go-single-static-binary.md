# 0001. Go, shipped as a single static binary

Date: 2026-09-20

## Status

Accepted

## Context

Zanskar is a security gateway that operators will run on hardened hosts, in containers, and
occasionally on a laptop for evaluation. Every extra runtime, shared library, or sidecar increases
the attack surface and the installation friction. The team's strongest language for network
services is Go.

Alternatives considered:

- **Java with an application server**. Mature, but heavy to deploy, and the
  JVM surface is large.
- **Rust**. Excellent memory safety and static linking, but the SSH, WinRM, and cloud SDK
  ecosystems are thinner and the team's velocity would be lower.
- **Node.js or Python**. Fast to prototype, but neither produces a self-contained artifact and both
  carry large transitive dependency trees, which is a supply-chain liability for a credential vault.

## Decision

Zanskar is written in Go. The gateway, the migration runner, the audit verifier, and the admin CLI
ship as one statically linked binary built with `CGO_ENABLED=0` and `-trimpath`. The container
image is distroless and runs as a non-root user. The frontend is embedded into the binary at build
time.

Dependencies are kept deliberately small. Adding a module requires a justification in the pull
request, and `go mod verify` runs in CI.

## Consequences

- One artifact to sign, scan, and deploy. SBOM generation is straightforward.
- No cgo means no FreeRDP binding, which is why RDP and VNC go through guacd (ADR 0002).
- SQLite must be a pure-Go implementation (ADR 0003).
- Memory safety for everything we write ourselves. The remaining C code is confined to guacd.
- Cross-compilation for Linux, macOS, and Windows on amd64 and arm64 is free.
