# 0045. Kubernetes clusters as targets: access through the gateway, as the person, every request on the record

Date: 2026-11-03

## Status

Accepted 2026-11-03 as recommended, and **parked**: the owner asked for the plan ("add Kubernetes
support as well, just like host, database, etc."), took the recommendations below as they stand
(phase 1 first; impersonation required, with a labelled shared-identity switch; port-forward off
by default; bodies never recorded; *Clusters*, `kube`, `pod`; the inventory tile settled when
phase 1 is built), and set the work aside for later. Nothing is built; the plan is the record.

Un-parked 2026-11-12 by [ADR 0048](0048-fabric.md), accepted the same day: clusters live in the
console's *Fabric* section under the tab *Kubernetes*, not *Clusters*, the dashboard counts them in
its *Fabric* tile, and phase 3 (EKS) is built before phase 2 (shells). Phase 1 is in progress on
`feat/fabric`.

## Context

Zanskar brokers hosts (SSH, RDP, VNC, WinRM), databases (ADR 0017) and web applications (ADR
0034). Teams with clusters hold what they always held: a kubeconfig with a long-lived token or a
cloud identity on each laptop, used from anywhere, for as long as it lasts, with the cluster's
audit log naming a service account or an IAM role rather than a person. The same brokering is
wanted for clusters: access gated by policy, approved and time-bound where it must be, with a
second factor, the cluster's credential never on the person's machine, every action attributable
to the person and on the record, nothing installed in the cluster.

Three facts shape the design.

1. **The API server is the standard.** Every Kubernetes, managed or not, speaks the same HTTPS API
   with the same authentication (bearer token, client certificate), the same RBAC and the same
   **impersonation**: a request carrying `Impersonate-User` and `Impersonate-Group` headers from a
   principal allowed to impersonate is authorised *as that user*, and the cluster's own audit log
   records that user. A broker can therefore act as the person without holding anything but the
   right to impersonate. Cloud clusters (EKS, GKE, AKS) differ only in how the broker's own token
   is minted — an adapter beside the standard path, never instead of it.
2. **`kubectl` is the client, and a kubeconfig is its interface.** People use kubectl, helm, k9s,
   their IDE. Access that does not work with a kubeconfig is not access. Yet most of what those
   tools do is plain HTTPS requests, and the rest (`exec`, `attach`, `port-forward`, `logs -f`) is
   an upgraded stream through the same API.
3. **A shell into a pod is a terminal.** It is what a host's SSH session is, and it deserves the
   same treatment: the browser terminal, the asciicast recording, command lines indexed and
   searched (ADR 0041), watched and ended by an administrator, four eyes (ADR 0042).

Zanskar's kinds are derived from a field on the target (an engine makes a database, an upstream an
application; `internal/protocol/protocol.go:53`), protocols are a closed list copied into CHECK
constraints, every session is recorded (`internal/connect/connect.go:367`), and a database's
"client" is a browser terminal: the person never receives a credential (ADR 0017). A cluster fits
that mould with one addition: a session a person drives from their own machine.

## Decision

1. **A cluster is a target kind, `kubernetes`, derived from `kube_api_server`.** Fields:
   `kube_api_server` (an https URL; the address rules of every kind apply), `kube_ca` (the
   cluster's CA bundle, PEM; empty means system roots), `kube_impersonate` (default true, see 2).
   A cluster serves two protocols: `kube` (the API) and `pod` (a shell into a container). It binds
   one credential, on the `kube` slot: a new credential type `kube_token` (a service-account bearer
   token) or `kube_client_cert` (certificate and key, PEM); user-supplied is not offered. Enrolment
   tests the credential against `/version`, asks `SelfSubjectAccessReview` whether it may
   impersonate users and groups, and lists namespaces, as a database enrolment tests its
   connection. Agentless (ADR 0009): the cluster needs RBAC objects, which the console prints, and
   nothing else.

2. **Zanskar's own credential needs only the right to impersonate.** Every request to the cluster
   goes out as the person: `Impersonate-User: <username>`, one `Impersonate-Group: zanskar:<group>`
   for each of the person's Zanskar groups the policy names, and `system:authenticated`. The
   cluster's RBAC decides what the person may do, bound to those groups by the cluster's
   administrator; the cluster's audit log shows the person. Zanskar holds no power of its own in
   the cluster beyond impersonation, so a stolen Zanskar credential is worth exactly what the
   cluster's own bindings allow it to impersonate, and no more. The console prints the manifest
   (a ClusterRole with `impersonate` on users and on the `zanskar:*` groups it knows, and its
   binding) so the administrator applies it rather than writing it. `kube_impersonate: false`
   makes every session act as the credential itself, for a cluster whose RBAC cannot be changed;
   the console and the audit log call such a session *shared identity*.

3. **The gateway is the API endpoint, in process.** A `kube` session mints a session token, as a
   database session mints its 30-second connect ticket, but living as long as the session: the
   person receives a kubeconfig whose `server` is the gateway
   (`https://<public url>/k8s/<session id>`), whose `token` is that session token and whose
   certificate authority is the gateway's own. kubectl, helm, k9s and an IDE work unchanged. The
   gateway reverse-proxies each request to the API server over TLS to the enrolled CA, swapping
   the session token for the vaulted credential and adding the impersonation headers; nothing
   else the person sends is forwarded as authentication. No container is involved, so this works
   on every deployment, the Helm chart's included, where application sessions do not (ADR 0034).
   A session ends when its grant does, after the policy's idle time without a request, or when an
   administrator ends it; the token is then refused and open streams are closed.

4. **The policy scopes namespaces; the gateway holds the line before the cluster does.** A grant of
   kind `kubernetes` carries `namespaces` (a list, or all), `cluster_scope` (cluster-wide resources:
   nodes, namespaces, CRDs; off by default) and `port_forward` (off by default). The gateway reads
   each request's path and refuses, with a 403 that says what the access covers, anything outside
   the namespaces or, without `cluster_scope`, any cluster-scoped request (`kubectl get pods -A`
   included). The cluster's RBAC stays the authority; the gateway's check is the guard-rail that
   keeps a misbound role from widening what a Zanskar policy granted. The usual fields apply:
   standing or approval, a second factor, time windows, idle and maximum minutes, retention. File
   transfer and developer tools do not apply; "own login" does not apply.

5. **Every request is the recording.** A `kube` session's recording is the sequence of its
   requests: time, verb, resource, namespace, name, the status the cluster answered, bytes, and
   for an upgrade the kind of stream and its length. It is written as an asciicast whose events
   are one marker and one line per request, so the player, the command index and *Find a
   command* (ADR 0041) work on it unchanged: a reviewer searches `delete deployments` across every
   cluster session as they search `rm -rf` across every SSH session. Request and response bodies
   are not recorded: they carry secrets. `exec` and `attach` streams are recorded as terminals
   (6). `port-forward` is recorded as a tunnel: the pod, the port and the bytes. `logs` is counted,
   not stored.

6. **`pod`: a shell into a container from the browser, like a host.** The portal lists the
   namespaces, pods and containers the person's access reaches (through the same impersonated
   proxy, so RBAC applies to the list too), and *Open* starts the exec stream and bridges it to
   the existing browser terminal (`web/src/pages/user/Terminal.tsx`, `/ws/pod`) with the asciicast
   recorder, command markers as SSH produces them, watching, termination and four eyes. The
   gateway speaks the API's WebSocket stream protocol (v5 channels, kubectl 1.31's default);
   SPDY is not spoken. A `pod` session needs no container on the gateway either.

7. **A kubectl terminal in the browser, for people without tooling (later).** As a database
   session runs the matching client in an ephemeral container (ADR 0017), a cluster can offer a
   browser terminal with kubectl, helm and k9s preloaded: the container's kubeconfig points at the
   gateway's own endpoint (3) with the session's token, so the container never holds the cluster's
   credential, and the per-request recording (5) stays complete. It needs the container runtime,
   a `zanskar-kubectl` image built and pinned per release, and the hardening of ADR 0017.

8. **Cloud adapters beside the standard path.** The standard path (a token or a certificate, any
   Kubernetes) ships first. Then EKS, because the gateway already knows its own AWS identity and
   assumes roles into customer accounts (ADR 0023): the credential type `kube_eks` names the
   cluster and the role, the gateway mints the presigned STS token the cluster accepts, lists the
   account's clusters for guided enrolment, and prints the `aws-auth`/access-entry step beside the
   RBAC manifest. GKE and AKS follow the same shape when asked for. Nothing above depends on them.

9. **The rest follows every other kind.** The configuration file (ADR 0043) and the Terraform
   provider (ADR 0044) carry a cluster by its fields and a `kubernetes` grant by its namespaces;
   the OpenAPI document gains the fields and the two protocols; the console CLI's `targets` lists
   clusters; the dashboard's inventory counts them; the audit log records `session.start` with
   protocol `kube` or `pod` and the namespaces granted, and `target.*` events as for any target.

## The plan

Sizes are for one engineer, with tests, against the files the survey of 2026-11-03 named.

**Phase 1 — clusters, and the API as the person (about three weeks).**
- Model: `kube_api_server`, `kube_ca`, `kube_impersonate` on `targets` (migration 0053, SQLite
  and Postgres alike); `Kind()` and `Validate` (`internal/target/target.go:465-660`), the list
  clause (`repo.go:112-118`), columns (`repo.go:25-28, 47-49, 289-290`), inventory
  (`repo.go:164-196`). Protocols `kube` and `pod` in `internal/protocol/protocol.go:57-74`,
  `target.go:28-66`, and the CHECK constraints on `target_credentials`, `access_sessions` and
  `access_requests`. Credential types `kube_token` and `kube_client_cert`
  (`internal/credential/credential.go:25-30, 159-236`).
- Enrolment: `TargetForm.tsx` kind *Kubernetes* (API server, CA, impersonate), `Bindings.tsx` slot
  `kube`, `TargetDetail.tsx` test (version, may impersonate, namespaces) and the RBAC manifest.
- Sessions: `POST /connect` protocol `kube` (`connect.go:380-394, 449-579`) issues the session
  token and answers the kubeconfig; a new package `internal/gateway/kubegw` with the impersonating
  reverse proxy at `/k8s/{session}/`, the namespace guard-rail, idle and maximum enforcement, the
  request recorder (asciicast markers) and termination (`internal/connect/revoke.go`); a session
  reaper for sessions without a socket. Upgrades (`exec`, `attach`, `port-forward`) pass through
  in phase 1 with the stream recorded as a tunnel; terminal recording of `exec` is phase 2.
- Policy: `Grant.Namespaces`, `ClusterScope`, `PortForward` (`internal/policy/policy.go:77-94,
  179-275, 311-358`), `PolicyEditor.tsx` and `policyModel.ts`.
- Portal: a *Clusters* tab in `user/Targets.tsx` with *Request* and *Kubeconfig* (shown once, copy
  or download, with its expiry); `admin/index.tsx` and a `Clusters.tsx` list; the dashboard tile.
- The rest: `configio` (doc.go, configio.go), the Terraform resource and its acceptance test,
  `docs/api/openapi.yaml`, the console CLI, the guide (`site/guide/index.html`, beside
  `#database` and `#applications`), this ADR accepted, release notes.
- Tests: unit tests for the guard-rail (paths, `-A`, cluster-scoped resources, impersonation
  headers, the token swap, nothing else forwarded as authentication) against a fake API server;
  a Playwright spec from enrolment to a `kubectl get` through the gateway against `kind` or a
  fake; the configio and Terraform round-trips.

**Phase 2 — shells (about two weeks).**
- `pod`: the WebSocket exec stream bridged to the browser terminal (`/ws/pod`), recorded as
  asciicast with markers, watched, ended, four eyes; the portal's namespace → pod → container
  picker through the impersonated proxy; `exec` and `attach` inside a `kube` session recorded as
  terminals the same way; `port_forward` gated by the policy.

**Phase 3 — EKS (about one and a half weeks), then GKE and AKS when asked.**
- `kube_eks` credential type; the presigned STS token; `eks:ListClusters`/`DescribeCluster`
  for guided enrolment; the access-entry step printed beside the RBAC manifest.

**Phase 4 — the kubectl terminal in the browser (about one week), if wanted after phase 1
shows who lacks tooling.**

## Consequences

- A cluster becomes "just another target": the same policies, approvals, second factor, time
  limits, recordings, reviews and audit, with the person named in the cluster's own audit log —
  which no shared kubeconfig gives.
- The gateway becomes a principal every enrolled cluster trusts to impersonate. The credential is
  sealed as every secret is (ADR 0005) and rotated in the vault alone; the manifest the console
  prints grants impersonation and nothing else, so the blast radius of a stolen credential is
  bounded by what the cluster lets Zanskar's groups do. This is the new trust to state in the
  threat model.
- Requests, not bytes, are recorded for `kube` sessions; bodies are not. A `kubectl apply` is on
  the record as a `PATCH` of a named resource, not its content. Recording write bodies, with
  secrets redacted, is a possible later addition, not the default.
- `watch` and `list` make noise: one line per request keeps a day of `k9s` to a few thousand
  lines; a long `watch` is one line with its length.
- A `kube` session has no socket, so its liveness is "a request within the idle time": a reaper
  ends it, and the portal shows it as open with its last request.
- The gateway's public certificate is what kubectl trusts; behind a proxy that terminates TLS
  (the live box) the kubeconfig carries nothing, as a browser carries nothing.
- SPDY streams from kubectl before 1.31 are not recorded; such a client is told to upgrade.
- Several copies of the kind and protocol tables (Go, console, OpenAPI, CHECKs) must change
  together; the survey lists them. A test that walks `protocol.Kinds` against each copy would
  stop the next drift.

## Open decisions, for the owner

1. **Order.** Phase 1 (the API as the person, kubeconfig for the person's own tools) before
   phase 2 (shells into pods)? Recommended: it covers everything kubectl does, including `exec`,
   from day one; the browser shell is the host-like comfort for people without tooling.
2. **Impersonation required**, with *shared identity* allowed only when switched on per cluster
   and labelled everywhere? Recommended yes.
3. **The inventory tile.** The dashboard's inventory row holds four tiles and the rule is four a
   row. Either *Clusters* joins and *Autoscaling groups* folds into the Hosts tile's detail
   ("3 Linux · 1 Windows · 2 groups"), or the row stays and clusters are counted elsewhere.
4. **`port-forward`:** off by default per policy, or never.
5. **Bodies:** never recorded (recommended), or the bodies of writes with secrets redacted.
6. **Names.** *Clusters* in the console; protocols `kube` and `pod`.

## Built (phase 1, 2026-11-13)

What the first build of the API-as-the-person settled, where the decision above left room:

1. **Scope across grants is the union.** When several grants admit a person to a cluster, the
   session reaches every namespace any of them names (every namespace, when any admits every
   namespace), and has `cluster_scope` or `port_forward` when any grant does. The clipboard and
   file-transfer switches take the strictest grant; scope does not, because a grant that admits
   a namespace admits it as a grant that admits a target does. `policy.Decision.Kube` carries it.
2. **A change of terms ends the session.** The proxy holds the scope and the groups it acts as
   for the session's life. The live re-check (ADR 0036) ends a `kube` session whose scope or
   groups would now differ, as it ends a session whose clipboard would now be off; the person
   connects again under the new terms.
3. **Cluster-wide means cluster-wide.** A request whose path names no namespace (nodes, the
   namespace list, `kubectl get pods -A`) needs `cluster_scope`, even for a grant that admits
   every namespace, as decision 4 says. `/api/v1/namespaces/{ns}` alone reads as a request in
   that namespace, so `kubectl get ns prod` works for a person granted prod. Paths outside the API
   (`/api`, `/apis`, `/version`, `/openapi`) are answered 404 and forwarded nowhere.
4. **Discovery is not recorded.** kubectl asks `/api`, `/apis/…` and `/openapi` a dozen times
   before its first real request; those pass under every scope and write no line. Every request
   that names a resource is one marker and one line, `{verb} {resource}[/{name}] [-n ns] → {status}`;
   an upgraded stream writes a line when it opens and one when it ends, with its length and bytes.
5. **An idle ceiling for a session without a socket.** A `kube` session whose policy sets no idle
   time still ends after eight hours without a request: a kubeconfig left on a laptop is not a
   standing credential. A bridge needs no such bound, since its socket ends with the browser tab.
   A session with an upgraded stream open (an `exec` shell) does not idle out while the stream
   carries bytes.
6. **The token.** `zk8s_` and 32 random bytes, kept hashed, compared in constant time, read from
   `Authorization: Bearer` only, refused the moment the session ends; a token that is not its
   session's own is refused the same way. The session's own context ends every request in flight
   and closes every upgraded stream.
7. **The kubeconfig carries the gateway's certificate only when it is self-signed** (the managed
   certificate before an upload): behind a certificate clients trust, or a proxy that terminates
   TLS, it carries none. It is shown once in the portal's *Clusters* tab, to copy or download,
   with the idle time and the end time when the policy sets a maximum.
8. **Shared identity is audited.** `session.start` says `acts_as: person` or
   `acts_as: shared identity`, beside the namespaces, `cluster_scope` and `port_forward`.
9. **The scope travels whole.** The configuration file (ADR 0043) and the Terraform provider
   (ADR 0044) carry a cluster's `kube_api_server`, `kube_ca`, `kube_platform` and
   `kube_impersonate`, and a grant's `namespaces`, `cluster_scope` and `port_forward`. A carrier
   that dropped them would import a grant to every namespace and turn a shared identity into
   impersonation; their tests read the receiving gateway's own answer, since two exports that
   both lost a field would still match.
10. **EKS, through a role (phase 3, built 2026-11-13).** The credential type `kube_eks` names
    the region, the role, the cluster and an ExternalId the gateway mints; it holds no secret.
    The token the cluster accepts is the one aws-iam-authenticator defined, a presigned STS
    `GetCallerIdentity` with the cluster's name in a signed header, minted as the role for each
    request and reused for twelve of the fifteen minutes the cluster accepts it, so an 8 h
    session never carries a stale one; a token AWS will not mint ends the request with a 502 that
    names the gateway's credential, not the cluster. The kube slot of a cluster whose platform is
    `eks` takes `kube_eks` and nothing else; every other platform takes a token or a certificate,
    the standard path, which GKE and AKS take too until adapters of their own exist. The role's
    page prints the three pastes (trust policy with the gateway's principal, permissions policy,
    the access-entry or `aws-auth` mapping to the user `zanskar`), tests the role (the stage that
    failed is named: `assume` or `describe`), and the Add cluster form fills the API server and
    CA from `DescribeCluster`. The RBAC manifest for an EKS cluster binds `kind: User` `zanskar`
    and prints the mapping instead of a ServiceAccount. `ListClusters` is in the client, not yet
    in the console. Not run against a real EKS cluster yet: the AWS test environment is torn
    down; the owner's gateway has the instance role.
11. **The gateway's credential failing is said as the gateway's fault.** A cluster that refuses
    Zanskar's own credential (a token rotated away, a role no longer mapped) answers the person a
    502 with a sentence naming the gateway's credential, logged for the administrator, where the
    API's 401 would have read as their kubeconfig being wrong. The session stays, to be used
    again once the credential is fixed. The same sentence covers a token AWS would not mint.
12. **An edit to the cluster ends its sessions.** A session holds the endpoint, CA, platform, the
    way it acts and the credential it started with for its life, so a change to any of them, or
    a credential bound or unbound on the kube slot, ends the cluster's live sessions as a
    disabled target's are; a tag or a note does not. Paths that try to leave the namespace
    through encoded slashes, encoded or plain dot segments or doubled slashes are refused by the
    gateway behind the real server mux, and nothing of them reaches the cluster (break-it,
    2026-11-14).
13. **Run against a real cluster (kind, Kubernetes v1.37.0, 2026-11-14).** The printed manifest
    applied as is, a service-account token on the kube slot, a policy granting the group `ops` the
    namespace `demo`: `kubectl` through the gateway created a pod, waited for it, ran `exec` over
    WebSocket (recorded as a stream with its byte counts), read events and Table output, and was
    refused `kube-system`, `nodes`, `-A` and `port-forward` with the gateway's sentences; the
    cluster's audit saw the person and `zanskar:ops`. Two findings, fixed: the cluster test asked
    whether it may impersonate groups without naming one, and RBAC answers a nameless review of a
    grant by `resourceNames` "no", so it reported `impersonate_groups: false` while impersonation
    worked (it asks for `system:authenticated` now); and `kubectl auth whoami` and `auth can-i`,
    reviews of the caller alone at paths that name no namespace, were refused as cluster-wide
    (every scope admits the three self-subject reviews now; a review of someone else stays
    cluster-wide).
