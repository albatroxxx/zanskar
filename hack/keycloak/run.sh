#!/usr/bin/env bash
# ADR 0035 against a real Keycloak: the user sync (people who join, leave and
# come back), a sign-in with Keycloak's password and one-time code and nothing
# asked by Zanskar, and a sign-out that ends Keycloak's session so the next
# sign-in asks for the password again. Everything runs in Docker on a private
# network, with no host ports: Keycloak over TLS with a throwaway certificate,
# and one container holding a Linux build of this tree and the scripted
# browser (e2e.py). Needs Docker, Go and openssl. About a minute, most of it
# Keycloak starting and one wait for a fresh one-time code.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p bin
W=$(mktemp -d "$PWD/bin/keycloak-e2e.XXXXXX") # under the repository: Docker on a VM shares the home directory
NET=zanskar-kc-e2e-$$
KC=zanskar-kc-e2e-$$
IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4.7}
cleanup() {
	docker rm -f "$KC" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$W"
}
trap cleanup EXIT
case "$(docker info --format '{{.Architecture}}')" in aarch64 | arm64) arch=arm64 ;; *) arch=amd64 ;; esac
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/zanskar" ./cmd/zanskar
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=kc -addext subjectAltName=DNS:kc -keyout "$W/kc.key" -out "$W/kc.pem" -days 1 2>/dev/null
chmod 644 "$W/kc.key" # Keycloak runs as its own user; the key is thrown away with $W
cp hack/keycloak/e2e.py hack/keycloak/inside.sh "$W/"
KC_ADMIN_PW=$(openssl rand -base64 18) # Keycloak's bootstrap admin, for this run only
docker network create "$NET" >/dev/null
docker run -d --name "$KC" --network "$NET" --network-alias kc -v "$W:/work:ro" \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" "$IMAGE" \
	start-dev --https-port=8443 --https-certificate-file=/work/kc.pem --https-certificate-key-file=/work/kc.key --hostname=https://kc:8443 >/dev/null
docker run --rm --network "$NET" -v "$W:/work:ro" -e KC_ADMIN_PW="$KC_ADMIN_PW" python:3.12-alpine sh /work/inside.sh
