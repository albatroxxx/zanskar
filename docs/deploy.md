# Deploying Zanskar

Zanskar is one static binary (the web UI is embedded) plus a PostgreSQL database and,
for RDP and VNC, a guacd sidecar. This guide covers a single node with Docker Compose
and a highly available Kubernetes deployment with the Helm chart in `deploy/helm/zanskar`.

## Topology

```
 browsers ──TLS──▶ load balancer / ingress ──TLS──▶ zanskar gateways (N pods)
                                                   │        │        │
                                                   │        │        └──▶ targets: SSH 22, WinRM 5986
                                                   │        └──▶ guacd (ClusterIP, isolated) ──▶ targets: RDP 3389, VNC 5900
                                                   └──▶ PostgreSQL          recordings: shared volume or S3
                                                        cloud APIs (autoscaling groups, via the pod identity)
```

- **Gateways** are stateless apart from two in-memory structures described under
  High availability. Everything durable is in PostgreSQL and the recordings store.
- **guacd** must only be reachable from gateway pods. It speaks an unauthenticated
  protocol and carries target credentials in flight (threat model, ADR 0002).
- **Recordings** are append-only files. Use a ReadWriteMany volume shared by all
  gateways, or object storage (the S3 backend is being added; the chart already wires
  `ZANSKAR_RECORDINGS_S3_BUCKET`).

## Guided single-node install

For a single instance, `zanskar init` writes the environment file the server reads
(ADR 0014): it asks for the listen address and TLS mode (own certificate, or behind a
TLS proxy on loopback), the data directory, whether to enable RDP and VNC, MFA and
logging; it generates the master key and prints the migrate and admin-create steps. It
runs non-interactively from flags for cloud-init or Ansible, and re-running it preserves
an existing master key.

```sh
sudo zanskar init                                              # interactive, writes /etc/zanskar/env
zanskar init --print --behind-proxy --data-dir /var/lib/zanskar   # preview to stdout
```

The rest of this guide sets the same variables by hand, for Docker Compose and Kubernetes.

## Single node with Docker Compose

`deploy/docker-compose.yml` runs PostgreSQL, guacd and the gateway. It publishes the
gateway on `127.0.0.1:8443` for a local trial. For anything reachable by other machines,
give the gateway a certificate: mount `tls.crt`/`tls.key` and set `ZANSKAR_TLS_CERT` and
`ZANSKAR_TLS_KEY`. The gateway refuses plain HTTP on a non-loopback address, so
`ZANSKAR_LISTEN_ADDR: 0.0.0.0:8443` in the compose file only works once TLS is
configured there (a note worth fixing in the compose file itself).

```sh
export ZANSKAR_MASTER_KEY=$(go run ./cmd/zanskar keygen)   # keep this safe
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml exec zanskar /zanskar migrate
docker compose -f deploy/docker-compose.yml exec -e ZANSKAR_ADMIN_PASSWORD=... zanskar \
  /zanskar admin create --username admin --name "Your Name"
```

## Kubernetes with the Helm chart

Prerequisites: a PostgreSQL 14+ database, a `kubernetes.io/tls` certificate for the
pods (cert-manager is the easy path), an ingress controller that supports WebSockets
and cookie affinity, and, for recordings with more than one replica, a ReadWriteMany
storage class or an S3 bucket.

1. **Secrets.** The chart reads `ZANSKAR_MASTER_KEY` and `ZANSKAR_DB_DSN` from an existing
   Secret and never writes secrets from values:

   ```sh
   kubectl create secret generic zanskar-secrets \
     --from-literal=ZANSKAR_MASTER_KEY="$(zanskar keygen)" \
     --from-literal=ZANSKAR_DB_DSN="postgres://zanskar:PASSWORD@db:5432/zanskar?sslmode=require"
   ```

2. **TLS in the pod.** Set `tls.secretName` to a `kubernetes.io/tls` Secret. It is mounted
   at `/tls` and wired to `ZANSKAR_TLS_CERT`/`ZANSKAR_TLS_KEY`. Terminating TLS at the
   ingress alone is not enough: the pod itself refuses to listen on plain HTTP. Use the
   ingress `backend-protocol: HTTPS` annotation (set in the default values) so the
   ingress re-encrypts to the pod.

3. **Install.**

   ```sh
   helm install zanskar deploy/helm/zanskar -n zanskar --create-namespace \
     -f my-values.yaml
   ```

   A pre-install/pre-upgrade hook Job runs `zanskar migrate`; the gateway refuses to
   start with migrations pending, so upgrades are a single `helm upgrade`.

4. **First admin.** There is no bootstrap endpoint on purpose:

   ```sh
   kubectl -n zanskar exec -it deploy/zanskar -- /zanskar admin create --username admin --name "Your Name"
   ```

5. **Autoscaling groups on EKS (IRSA).** Give the gateway pods an IAM role by annotating
   the service account (`serviceAccount.annotations: eks.amazonaws.com/role-arn: ...`).
   That role is the principal that assumes each group's cross-account role with the
   ExternalId Zanskar generated; set `config.awsGatewayPrincipal` to the same ARN so the
   trust policy shown to admins is correct. The per-group role needs only the
   permissions the admin UI renders (Describe calls, console output, Instance Connect).

6. **Ingress affinity.** Two requests must land on the same pod: `POST /api/v1/connect`,
   which issues a short-lived ticket held in that pod's memory, and the `GET /ws/*`
   upgrade that redeems it within 30 seconds. Behind an ingress, client IPs are NATed,
   so use cookie affinity; the default values carry the ingress-nginx annotations
   (`affinity: cookie`, `session-cookie-name: zanskar_pod`, one-hour proxy timeouts for
   long WebSocket sessions). The Service defaults to `sessionAffinity: ClientIP` for
   setups without an ingress.

## High availability

Run two or more gateway replicas behind the ingress. What lives where:

| State | Location | Shared across pods |
|---|---|---|
| Users, policies, targets, credentials (sealed), audit chain, sessions | PostgreSQL | yes |
| Recordings | RWX volume or S3 | yes |
| Connect tickets (30 s, single use) | pod memory | no, hence affinity |
| Live-session registry (what is connected right now) | pod memory | no |
| Autoscaling sync loop | every pod runs it | duplicated polls, idempotent writes |

Consequences, stated plainly:

- **Admin "terminate" and auditor "shadow" act on the pod that receives the request.**
  If the session lives on another pod, terminate closes the database row (the session
  shows as ended) but the live connection keeps running until its own bridge notices,
  and shadow returns "not live here". With cookie affinity an admin who terminates a
  session usually lands on a different pod than the user. Mitigations today: run a
  single gateway replica where live control matters, or put admins behind their own
  pod via the separate admin listener. A cross-pod control channel (Postgres LISTEN/
  NOTIFY or a small pub/sub) is the planned fix and is tracked in the roadmap.
- **Autoscaling sync runs on every pod.** Polls are duplicated; the writes are
  idempotent upserts, so this costs API calls, not correctness. A leader election is a
  follow-up.
- The audit chain is serialised with a database advisory lock, so many pods appending
  concurrently stay consistent (ADR 0008).

## Upgrades and migrations

Migrations are explicit and forward-only. The chart's hook Job applies them before the
new pods start; outside Helm, run `zanskar migrate` yourself before restarting. Take a
database backup first. Rolling updates keep at least one pod (PodDisruptionBudget);
`terminationGracePeriodSeconds` gives live sessions a minute to close.

## Backups and key custody

- **PostgreSQL**: regular dumps or PITR. The audit chain, recordings index and every
  sealed secret live here.
- **Recordings**: back up the volume or bucket; the database rows reference them by URI
  and carry their SHA-256 for integrity checks.
- **`ZANSKAR_MASTER_KEY`**: escrow it in a vault the database backup cannot reach. Every
  vaulted credential, identity-provider secret and authenticator secret is sealed under
  keys wrapped by it (ADR 0007). Without it a restored database is a list of ciphertext.
  Rotating it is supported by the key ring (`key_versions`); losing it is not.

## Security checklist

- TLS on the pod (`tls.secretName`) and on the ingress; HSTS is sent automatically when
  the gateway serves TLS.
- guacd isolated by the NetworkPolicy the chart installs; never expose port 4822.
- `ZANSKAR_REQUIRE_MFA=true` (default). Do not turn it off outside throwaway installs.
- Cookies are `Secure`, `HttpOnly`, `SameSite=Strict` when TLS is on; do not set
  `ZANSKAR_TRUST_PROXY_TLS` in the in-pod TLS mode.
- Recordings volume: only the gateway identity can read it; the API records every view.
- Gateway pods run as non-root on a distroless image with a read-only root filesystem
  and all capabilities dropped; keep `readOnlyRootFilesystem` when adding sidecars.
- Ship the audit log to your SIEM: `ZANSKAR_SIEM_SYSLOG_ADDR` (syslog/CEF),
  `ZANSKAR_SIEM_WEBHOOK_URL` with `ZANSKAR_SIEM_WEBHOOK_SECRET` (signed JSON). These are
  being added alongside this chart and are described in the configuration reference;
  pass them through `config.extraEnv` / `config.extraEnvFrom`.
- Verify the audit chain on a schedule: `zanskar audit verify` from a CronJob.
- Keep guacd at 1.6 or newer (certificate pinning, ADR 0012); Dependabot tracks the
  compose image, and `guacd.image.tag` in the chart.
