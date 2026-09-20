# 0004. Apache License 2.0

Date: 2026-09-20

## Status

Accepted

## Context

Zanskar is open source. The license shapes who will adopt it, who will contribute, and whether
we can depend on guacd and guacamole-common-js, which are Apache 2.0.

Alternatives considered:

- **AGPL 3.0.** Protects against a cloud provider offering Zanskar as a hosted service without
  contributing back. It also deters many enterprises whose legal teams refuse AGPL, and it
  complicates combining with Apache-licensed code.
- **MIT or BSD.** Maximally permissive, but no explicit patent grant.
- **Business Source License.** Not open source by the OSI definition, which contradicts the goal.

## Decision

Zanskar is licensed under the Apache License 2.0. Contributions are accepted under the same
license through the Developer Certificate of Origin, signed by a `Signed-off-by` trailer on each
commit.

## Consequences

- Full compatibility with guacd, guacamole-common-js, and the Go ecosystem.
- Explicit patent grant for users and contributors.
- Anyone, including cloud providers, may run Zanskar commercially. We accept this.
- Every source file carries a short SPDX header: `SPDX-License-Identifier: Apache-2.0`.
