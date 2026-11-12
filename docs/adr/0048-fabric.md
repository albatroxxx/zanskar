# 0048. Fabric: what Zanskar reaches through a control plane, where the members come and go

Date: 2026-11-12

## Status

Accepted 2026-11-12. Proposed the same day on the owner's instruction: "start working on a new
section called Fabric. We will bring auto scaling groups inside the Fabric section. Additionally,
in Fabric section, we will include the dynamically created resources, for example, Kubernetes,
Docker containers, ECS clusters, and the access for them will be managed from the Zanskar portal."
The owner then narrowed it: "Let's only add services which fit the criteria, like Kubernetes
(EKS)", and confirmed nobody else is building Kubernetes ("teammates are not working on it. we
need to put work on them now"). So Fabric holds autoscaling groups and Kubernetes clusters, EKS
as Kubernetes' cloud adapter; Docker hosts and ECS clusters are not in scope (see 7). F0 is
built; F1 (Kubernetes, the API as the person) follows on the same branch.

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
   *Kubernetes* once it is built (no tab before its kind exists). The navigation
   stays as long as it is: Autoscaling's item becomes Fabric's, and `/admin/autoscaling` redirects
   to `/admin/fabric/autoscaling`. The dashboard's inventory keeps four tiles: *Fabric* replaces
   *Autoscaling groups*, its detail counting each kind. This settles ADR 0045's open question 3.
   Considered and not taken: a navigation group with a heading and a sub-item per kind, which
   adds a line per kind to an already long list.

2. **Names.** The tabs are *Autoscaling* and *Kubernetes*. ADR 0045 named Kubernetes clusters
   *Clusters*; beside other control planes that word says too little, so it is amended to
   *Kubernetes*. The protocols ADR 0045 chose (`kube`, `pod`) stand.

3. **The model every kind shares.** A Fabric resource is a target whose kind is derived, as every
   kind is (`internal/protocol/protocol.go:53`), from the control plane's field: an autoscaling
   group (as today), `kube_api_server` for a cluster. It binds the control
   plane's credential, is tested at enrolment against the control plane, and its members are read
   live from it. Members are not stored, except where a member carries trust Zanskar must keep:
   autoscaling instances keep their table, because each pins a host key and certificates (ADR
   0024). A pod, a container or a task is named in the session and its recording, not kept.

4. **Access is a grant on the control plane with a scope**, in the policy model of ADR 0036: a
   grant of the kind's own type names the resource (by name or tag, as every grant does) and a
   scope the gateway enforces before the control plane does:
   - Autoscaling: the group (as today).
   - Kubernetes: namespaces, cluster scope, port-forward (ADR 0045, 4).

   Standing or approval, a second factor, time windows, idle and maximum minutes and retention
   apply as on every grant.

5. **A shell into a member is a terminal session**: the browser terminal, the asciicast recording
   with command markers, the command index and *Find a command* (ADR 0041), watching, termination
   and four eyes, as for SSH. Kubernetes adds the API as the person through a per-session
   kubeconfig (ADR 0045, 3); the other kinds have no client of their own to serve.

6. **Kubernetes is ADR 0045, unchanged** but for its name (2) and its tile (1).

7. **Docker hosts and ECS clusters are not in scope.** The criterion the owner set is a control
   plane whose members Zanskar reaches as the person, on the record, with nothing installed: a
   Kubernetes API server meets it through impersonation and its own audit log. A Docker Engine
   gives a root-equivalent credential with no notion of who is asking, and ECS reaches a task
   only through AWS's session protocol; both were considered (the proposal recorded a design for
   each) and declined on 2026-11-12. A control plane that meets the criterion can join later by
   the same model (3, 4, 5).

8. **The rest follows every other kind**: configuration file (ADR 0043), Terraform (ADR 0044),
   OpenAPI, the console CLI, the dashboard, lifecycle declarations (ADR 0047), the guide.

## The plan

Sizes are for one engineer, with tests.

- **F0 — the section (two days; built).** *Fabric* in the navigation and its page with the
  *Autoscaling* tab; the redirect; the dashboard tile; the guide. Nothing else changes, including
  the portal (see the open decisions).
- **F1 — Kubernetes, the API as the person (about three weeks).** ADR 0045 phase 1.
- **F2 — Kubernetes shells (about two weeks).** ADR 0045 phase 2, after F3.
- **F3 — EKS adapter (about one and a half weeks).** ADR 0045 phase 3, built right after F1
  rather than after the shells: the owner's clusters are EKS.

## Consequences

- A person asks for a Kubernetes namespace the way they ask for a host, and every request and
  every shell is on the record like an SSH session. Nothing is installed in the cluster.
- Each new kind is a cross-cutting change: the kind derivation copied in seven places, the closed
  protocol list and its CHECK constraints, a grant type (ADR 0036), lifecycle declarations and
  their labels (ADR 0047), configio, Terraform, OpenAPI and the CLI. The phase sizes include it.
- Autoscaling moves in the console; its API paths, events and grants do not change.

## Decisions taken, 2026-11-12

1. **Who builds Kubernetes:** this project does; the teammate handed ADR 0045 on 2026-11-04 is
   not working on it (the owner).
2. **Scope:** Kubernetes, with EKS as its adapter. Docker and ECS declined (7).
3. **Order:** F1 the API as the person, F3 EKS, F2 shells.
4. **The user portal:** its tabs stay per kind (Hosts, Databases, Applications, Autoscaling, then
   Kubernetes), since people connect to things and not to the console's grouping. Taken as
   recommended.
