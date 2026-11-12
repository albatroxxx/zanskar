# 0048. Fabric: what Zanskar reaches through a control plane, where the members come and go

Date: 2026-11-12

## Status

Proposed 2026-11-12, on the owner's instruction: "start working on a new section called Fabric. We
will bring auto scaling groups inside the Fabric section. Additionally, in Fabric section, we will
include the dynamically created resources, for example, Kubernetes, Docker containers, ECS
clusters, and the access for them will be managed from the Zanskar portal." Phase F0 (the section,
with autoscaling groups moved into it) is built on `feat/fabric`; every later phase waits for the
open decisions at the end.

## Context

Zanskar's inventory is things that stay put: a host at an address, a database at an endpoint, an
application at a URL. Each is enrolled once, probed, pinned and granted by name or tag.

Autoscaling groups (ADRs 0011, 0023, 0024) were the first exception: Zanskar enrols the *group*,
through the gateway's AWS identity and a role in the customer's account, and the instances are
discovered, pinned per instance, joined and retired as the group scales; a person connects to an
instance, or to the newest healthy one, and fails over when it goes. What is granted is the group;
what a session reaches is a member that may not exist tomorrow.

The resources the owner names have the same shape:

- **Kubernetes** (ADR 0045, accepted and parked 2026-11-03): an API server enrolled once; pods and
  containers come and go; access is the API as the person, plus shells into containers.
- **Docker containers**: a Docker host enrolled once; containers come and go with deployments;
  access is a shell into a running container. Read plainly, "Docker containers" means *shells into
  containers on Docker hosts people operate*. Running containers for people (a sandbox, a
  workbench) is a different feature and not this one.
- **ECS clusters**: a cluster enrolled once through an AWS role; services scale tasks up and down;
  access is a shell into a task's container through ECS Exec.

In every case the thing enrolled is a **control plane** (the EC2 Auto Scaling API, a Kubernetes API
server, a Docker Engine, the ECS API), Zanskar's credential is for that control plane, the
**members** are read from it rather than enrolled one by one, and a grant names the control plane
and a **scope** within it (a group, namespaces, container labels, services).

## Decision

1. **Fabric is a section of the console for control planes and their members.** One item in the
   admin navigation, *Fabric*, opens a page with a tab per kind: *Autoscaling* first, then
   *Kubernetes*, *Docker*, *ECS* as each is built (no tab before its kind exists). The navigation
   stays as long as it is: Autoscaling's item becomes Fabric's, and `/admin/autoscaling` redirects
   to `/admin/fabric/autoscaling`. The dashboard's inventory keeps four tiles: *Fabric* replaces
   *Autoscaling groups*, its detail counting each kind. This settles ADR 0045's open question 3.
   Considered and not taken: a navigation group with a heading and a sub-item per kind, which
   adds a line per kind to an already long list.

2. **Names.** The tabs are *Autoscaling*, *Kubernetes*, *Docker* and *ECS*. ADR 0045 named
   Kubernetes clusters *Clusters*; with ECS beside it that word means two things, so it is
   amended to *Kubernetes*. The protocols ADR 0045 chose (`kube`, `pod`) stand.

3. **The model every kind shares.** A Fabric resource is a target whose kind is derived, as every
   kind is (`internal/protocol/protocol.go:53`), from the control plane's field: an autoscaling
   group (as today), `kube_api_server`, `docker_endpoint`, `ecs_cluster`. It binds the control
   plane's credential, is tested at enrolment against the control plane, and its members are read
   live from it. Members are not stored, except where a member carries trust Zanskar must keep:
   autoscaling instances keep their table, because each pins a host key and certificates (ADR
   0024). A pod, a container or a task is named in the session and its recording, not kept.

4. **Access is a grant on the control plane with a scope**, in the policy model of ADR 0036: a
   grant of the kind's own type names the resource (by name or tag, as every grant does) and a
   scope the gateway enforces before the control plane does:
   - Autoscaling: the group (as today).
   - Kubernetes: namespaces, cluster scope, port-forward (ADR 0045, 4).
   - Docker: containers matched by label or name pattern, and the user an exec runs as.
   - ECS: services (or all), and the container name within the task.

   Standing or approval, a second factor, time windows, idle and maximum minutes and retention
   apply as on every grant.

5. **A shell into a member is a terminal session**: the browser terminal, the asciicast recording
   with command markers, the command index and *Find a command* (ADR 0041), watching, termination
   and four eyes, as for SSH. Kubernetes adds the API as the person through a per-session
   kubeconfig (ADR 0045, 3); the other kinds have no client of their own to serve.

6. **Kubernetes is ADR 0045, unchanged** but for its name (2) and its tile (1).

7. **Docker: the host's own SSH first, the Engine API over mutual TLS second.** Two ways reach a
   Docker Engine without an agent:
   - *A. A Docker host enrolled on its own*, at `tcp://host:2376`, with a client certificate (a
     new credential type `docker_tls`), the Engine's documented remote protection. The daemon must
     listen on the network, which most hosts are configured never to do.
   - *B. An existing Linux host marked as running Docker*: the gateway opens the Engine API over
     the host's SSH session, as Docker's own `ssh://` transport does (`docker system dial-stdio`),
     reusing the host's pinned key and SSH credential. The SSH user must be in the `docker` group.

   Recommended: B first. Nothing new is exposed on the host, the host's trust is already pinned,
   and most Docker hosts are already Linux hosts in Zanskar. A follows for hosts whose operators
   prefer a TLS endpoint. Either way the credential is root-equivalent on the host, far more than
   Kubernetes' impersonation, so the gateway holds three lines of its own: an exec runs as the user
   the grant names (the container's default user if none, never `root` unless the grant says
   so), never `Privileged`, and only in containers the grant's labels or names match; the gateway
   calls only the container list, inspect and exec endpoints, and refuses the rest.

8. **ECS: the AWS adapter, through the role autoscaling already uses.** The standard path for
   containers is the Docker Engine API and the Kubernetes API (vendor-neutral, as everywhere in
   Zanskar); ECS is AWS's by nature and sits beside them. The gateway assumes the customer's role
   (ADR 0023), lists clusters, services and tasks (`ecs:List*`, `ecs:Describe*`) and opens a shell
   with `ecs:ExecuteCommand`, which answers with an SSM session; the gateway speaks the SSM
   session protocol to it and bridges it to the browser terminal. Every assume-role call sets
   `SourceIdentity` to the person's Zanskar username, so CloudTrail names the person, not only the
   role. The console prints the role's policy and the two prerequisites ECS Exec needs on the
   customer's side (`enableExecuteCommand` on the service, the SSM permissions on the task role).

9. **The rest follows every other kind**: configuration file (ADR 0043), Terraform (ADR 0044),
   OpenAPI, the console CLI, the dashboard, lifecycle declarations (ADR 0047), the guide.

## The plan

Sizes are for one engineer, with tests.

- **F0 — the section (two days; built).** *Fabric* in the navigation and its page with the
  *Autoscaling* tab; the redirect; the dashboard tile; the guide. Nothing else changes, including
  the portal (see the open decisions).
- **F1 — Kubernetes, the API as the person (about three weeks).** ADR 0045 phase 1.
- **F2 — Kubernetes shells (about two weeks).** ADR 0045 phase 2.
- **F3 — Docker over the host's SSH (about two weeks).** The *runs Docker* mark on a Linux host
  and its test (`/version`, `/containers/json` over `dial-stdio`); the grant's labels, names and
  exec user; the container picker in the portal; exec bridged to the terminal, recorded; the
  *Docker* tab listing hosts and their running containers.
- **F4 — ECS (about two and a half weeks).** Enrolment through the role, with the printed policy;
  clusters, services and tasks; the SSM session protocol in Go (the data channel's framing,
  acknowledgements and handshake), bridged to the terminal and recorded; `SourceIdentity`.
- **F5 — EKS adapter (about one and a half weeks)**, ADR 0045 phase 3; **F6 — Docker over the
  Engine API with TLS** (about one week) when asked for.

## Consequences

- A person asks for a Kubernetes namespace, a set of containers or an ECS service the way they ask
  for a host, and every shell is on the record like an SSH session. Nothing is installed on a
  host, a cluster or a task.
- Each new kind is a cross-cutting change: the kind derivation copied in seven places, the closed
  protocol list and its CHECK constraints, a grant type (ADR 0036), lifecycle declarations and
  their labels (ADR 0047), configio, Terraform, OpenAPI and the CLI. The phase sizes include it.
- Docker's credential is root-equivalent on the host; the gateway's guard rails (7) narrow what
  Zanskar does with it, but whoever holds the gateway's vault holds the hosts. The console says so
  where the mark is set.
- ECS adds an implementation of AWS's session protocol to maintain; AWS publishes its reference
  client (Apache 2.0) to follow.
- Autoscaling moves in the console; its API paths, events and grants do not change.

## Open decisions, for the owner

1. **Who builds Kubernetes?** ADR 0045 was handed to a teammate on 2026-11-04
   (`feat/kubernetes-clusters`); no branch reached GitHub and nothing is built. If the teammate is
   still on it, F1–F2 are theirs and Fabric's next phase here is F3 or F4.
2. **Order after F0.** Recommended: Kubernetes (designed and accepted), then Docker, then ECS. If
   the clusters people use today are ECS, ECS first.
3. **Docker: B (the host's SSH) first, A (Engine API over TLS) later?** Recommended yes. And may a
   grant let an exec run as `root`, or never?
4. **ECS: the SSM session protocol in the gateway** (recommended: no container, works on the Helm
   deployment), or AWS's `session-manager-plugin` run in a container beside the gateway (less code
   of ours, but the container runtime and its image become a requirement for ECS).
5. **The user portal.** Recommended: its tabs stay per kind (Hosts, Databases, Applications,
   Autoscaling, then Kubernetes, Docker, ECS as they come), since people connect to things and not
   to the admin's grouping; or one *Fabric* tab mirroring the console.
