#!/usr/bin/env bash
# ADR 0035 against a real Authentik, a second vendor, so the identity
# features are shown to be the standards' and not Keycloak's: Authentik
# pushes people to the gateway over SCIM 2.0 (joiner, deactivation,
# reactivation, deletion), a person signs in over OIDC with an email-form
# username and nothing asked by Zanskar, and signs out. It runs twice: with
# Authentik's provider sign-out set to end Authentik's own session (the
# set-up the guide recommends), and with Authentik's default flow, which
# keeps it, and the provider's "ask for the password at every sign-in".
# Everything runs in Docker on a private network, with no host ports:
# Postgres, Authentik's server and worker, nginx giving it TLS as
# https://ak, and one container with a Linux build of this tree and the
# scripted browser (e2e.py). Needs Docker, Go and openssl. A few minutes,
# most of it Authentik starting.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p bin
W=$(mktemp -d "$PWD/bin/authentik-e2e.XXXXXX") # under the repository: Docker on a VM shares the home directory
N=zanskar-ak-e2e-$$
IMAGE=${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server:2026.8.5}
cleanup() {
	docker rm -f "$N-pg" "$N-server" "$N-worker" "$N-tls" >/dev/null 2>&1 || true
	docker network rm "$N" >/dev/null 2>&1 || true
	rm -rf "$W"
}
trap cleanup EXIT
case "$(docker info --format '{{.Architecture}}')" in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/zanskar" ./cmd/zanskar
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=ak -addext subjectAltName=DNS:ak -keyout "$W/ak.key" -out "$W/ak.pem" -days 1 2>/dev/null
chmod 644 "$W/ak.key" # nginx reads it as its own user; it is thrown away with $W
cp hack/authentik/e2e.py hack/authentik/inside.sh "$W/"
cat > "$W/nginx.conf" <<NGINX
events {}
http {
  server {
    listen 443 ssl;
    server_name ak;
    ssl_certificate /w/ak.pem;
    ssl_certificate_key /w/ak.key;
    location / {
      proxy_pass http://ak-server:9000;
      proxy_http_version 1.1;
      proxy_set_header Host \$host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For \$remote_addr;
    }
  }
}
NGINX
# Secrets for this run only.
PG_PW=$(openssl rand -hex 16)
AK_KEY=$(openssl rand -hex 32)
AK_TOKEN=$(openssl rand -hex 24)
ak_env=(-e AUTHENTIK_SECRET_KEY="$AK_KEY" -e AUTHENTIK_POSTGRESQL__HOST=ak-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
	-e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PW" -e AUTHENTIK_POSTGRESQL__NAME=authentik)
docker network create "$N" >/dev/null
docker run -d --name "$N-pg" --network "$N" --network-alias ak-pg -e POSTGRES_USER=authentik -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_DB=authentik postgres:16-alpine >/dev/null
sleep 3
docker run -d --name "$N-server" --network "$N" --network-alias ak-server "${ak_env[@]}" \
	-e AUTHENTIK_BOOTSTRAP_TOKEN="$AK_TOKEN" -e AUTHENTIK_BOOTSTRAP_PASSWORD="$(openssl rand -hex 16)" -e AUTHENTIK_BOOTSTRAP_EMAIL=admin@corp.example \
	"$IMAGE" server >/dev/null
docker run -d --name "$N-worker" --network "$N" "${ak_env[@]}" "$IMAGE" worker >/dev/null
docker run -d --name "$N-tls" --network "$N" --network-alias ak -v "$W:/w:ro" nginx:alpine nginx -c /w/nginx.conf -g 'daemon off;' >/dev/null
echo "waiting for Authentik and its default flows..."
ready=$(cat <<'PY'
import json, os, sys, urllib.request
h = {"Authorization": "Bearer " + os.environ["AK_TOKEN"]}
def n(path):
    try:
        return json.load(urllib.request.urlopen(urllib.request.Request("http://ak-server:9000/api/v3" + path, headers=h), timeout=5))["pagination"]["count"]
    except Exception:
        return 0
sys.exit(0 if n("/flows/instances/?slug=default-provider-authorization-implicit-consent") and n("/flows/instances/?slug=default-invalidation-flow") and n("/propertymappings/provider/scim/") else 1)
PY
)
for _ in $(seq 1 90); do
	docker run --rm --network "$N" -e AK_TOKEN="$AK_TOKEN" python:3.12-alpine python3 -c "$ready" && break
	sleep 5
done
for mode in logout prompt; do
	echo "=== Authentik, mode: $mode"
	docker run --rm --name "$N-zk" --network "$N" --network-alias zk -e AK_MODE="$mode" -e AK_TOKEN="$AK_TOKEN" -v "$W:/w:ro" python:3.12-alpine sh /w/inside.sh
done
