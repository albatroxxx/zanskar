# Security rules every change keeps

Zanskar is a security product: a mistake here is somebody else's incident. These are the rules a
change is checked against before anything else; [docs/threat-model.md](../threat-model.md) says
what they defend.

## Secrets

- A secret is sealed with the keyring (`keyring.Ring.Encrypt(keyring.AAD(table, id), …)`) and the
  key version is stored beside the ciphertext, so a row cannot be moved to another table or id
  and still open. Rotation is `zanskar key rotate-master`; every table that holds a sealed value
  is in the rotation list in `cmd/zanskar/key.go`.
- A secret is never logged, never in an audit event's details, never in an error message, never in
  a URL, never echoed back by the API (`has_password: true` is the most a response says). Test
  values in fixtures are obviously fake.
- A per-session credential (a ticket, a session certificate, a relay's upstream password) lives in
  the container or the process that needs it and nowhere a person can read it; a client the person
  drives never authenticates itself (ADR 0017).
- The gateway's own identity is held at least privilege: an SSH CA that signs for a session, an
  AWS role that describes instances, a cluster credential that may only impersonate.

## Every route, every mutation

- Every handler is behind `auth.RequireAuth` or `auth.RequireRole`; the API refuses what the UI
  hides. A sensitive setting asks for a fresh authenticator code (step-up).
- Every mutation records an `audit.Event` through `audit.Actor{…}.Event(…)`, with the actor, the
  object and details that **never contain secrets**. Every action has a console label
  (`TestActionsMatchConsoleLabels`), and a label is a sentence, not the action's words.
- Reading content (a recording, a search of what sessions printed, the audit log itself) is
  recorded too. What a person may see of their own account is scoped (`audit.Filter.OwnActions`):
  the access portal never shows another person's address or another person's events.

## Addresses and egress

- A target's address passes the address rules (`internal/target/forbidden.go`): the gateway's own
  listener, loopback, link-local and cloud metadata addresses are refused on create and on
  update, by hand and by import.
- Session containers reach only what their session is for: a database relay its endpoint, an
  application relay its origins and, under *Any public address*, public addresses through an
  inspecting proxy that refuses private, link-local, metadata, CGNAT, documentation, NAT64,
  6to4, Teredo and the browser's own services (`internal/ipspace`). Private hosts are opt-in per
  application. The session browser's own address bar is held to the origins.
- Containers run with no new privileges, a read-only root, dropped capabilities, memory limits, a
  per-session network, and a reaper; images are pinned by digest and scanned.

## Say the posture first

When a release makes any session able to reach more than before, or lets the gateway read what it
did not read, the release note's first paragraph says so in bold and tells the operator what to do
about it before they upgrade (1.17.0: every application widens to public dependencies; 1.18.0: the
relay reads a session's HTTP in clear under *Any public address*). The pull request body says the
same. Nothing of this kind is ever folded into an "Improvements" list.

## Scanners are answered, not silenced

CodeQL, gosec, govulncheck, Trivy and SonarCloud run in CI. A finding is fixed, or dismissed as a
false positive **with the reason written** in the dismissal (at most 280 characters) or in a
`// NOSONAR` / `// #nosec` comment beside the line. "It's fine" is not a reason; "JSON log handler
escapes every value" is. A dependency bump that closes a CVE goes in the next release and the
note says which.

## Agentless, vendor-neutral, and honest about trust

Nothing is installed on a target. Standards (OIDC, SCIM, LDAP, the Kubernetes API) come first and
vendor adapters sit beside them. The threat model is updated when a new trust appears (a gateway
credential a cluster trusts to impersonate is one), and the documentation says what an operator
is trusting Zanskar with, in plain words.
