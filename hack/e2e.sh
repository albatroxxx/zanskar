#!/usr/bin/env bash
# Browser end-to-end test: a real Chromium drives the console against a real
# gateway binary and the fake SSH server, the way hack/smoke.sh drives the API.
# Run after building bin/zanskar (with the console: make build) and bin/fakessh,
# and after `./node_modules/.bin/playwright install chromium` in web/. The target is enrolled
# by this machine's LAN address, because the gateway refuses loopback ones;
# set SMOKE_LAN_IP when it cannot be found. The data the browser needs (a
# group, a credential, a trusted target, a policy) is seeded through the API:
# the browser tests are about what a person does, not about re-typing setup.
set -euo pipefail
cd "$(dirname "$0")/.."
S=${E2E_TMP:-$(mktemp -d)}
LAN=${SMOKE_LAN_IP:-$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')}
[[ -n "$LAN" ]] || { echo "no LAN address found; set SMOKE_LAN_IP" >&2; exit 1; }
PORT=${E2E_PORT:-18444}
SSHPORT=${E2E_SSH_PORT:-2225}
HTTPPORT=${E2E_HTTP_PORT:-8083}
TLSPORT=${E2E_TLS_PORT:-18445}
stop() { for port in "$PORT" "$SSHPORT" "$HTTPPORT" "$TLSPORT"; do lsof -ti "tcp:$port" 2>/dev/null | xargs kill 2>/dev/null || true; done; }
stop; sleep 0.5
trap stop EXIT
rm -rf "$S/e2e.db" "$S/e2e.db-wal" "$S/e2e.db-shm" "$S/rec" "$S/jar" "$S/tls"

( ./bin/fakessh "0.0.0.0:$SSHPORT" > "$S/fakessh.log" 2>&1 & )
# The toy web application, reached by the gateway at the LAN address like any upstream.
( ./bin/fakehttp -origin "http://$LAN:$HTTPPORT" "0.0.0.0:$HTTPPORT" > "$S/fakehttp.log" 2>&1 & ); sleep 0.5
export ZANSKAR_DB_DSN="file:$S/e2e.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" ZANSKAR_LOG_FORMAT=text ZANSKAR_LISTEN_ADDR=127.0.0.1:$PORT ZANSKAR_REQUIRE_MFA=false ZANSKAR_RECORDINGS_DIR=$S/rec
export ZANSKAR_MASTER_KEY_FILE= ZANSKAR_TLS_MODE=
./bin/zanskar migrate >/dev/null 2>&1
ZANSKAR_ADMIN_PASSWORD='bootstrap passphrase 2026' ./bin/zanskar admin create --username root --name "First Admin" >/dev/null
ZANSKAR_MASTER_KEY=$(./bin/zanskar keygen); export ZANSKAR_MASTER_KEY
( ./bin/zanskar serve > "$S/gateway.log" 2>&1 & )
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null || { echo "gateway did not come up"; cat "$S/gateway.log"; exit 1; }

B=http://127.0.0.1:$PORT/api/v1
J=$S/jar
login=$(curl -s -c "$J" -X POST "$B/auth/login" -H 'Content-Type: application/json' -d '{"username":"root","password":"bootstrap passphrase 2026"}')
CSRF=$(echo "$login" | python3 -c 'import sys,json; print(json.load(sys.stdin)["csrf_token"])')
ROOT=$(echo "$login" | python3 -c 'import sys,json; print(json.load(sys.stdin)["user"]["id"])')
api() { curl -s -b "$J" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
GRP=$(api -X POST "$B/groups" -d '{"name":"ops","description":"operators"}' | jget 'd["id"]')
# A second account with the user role alone, in the same group, so the browser
# suite can prove what a non-administrator cannot reach. The password is kept
# as set (must_change_password false) so the suite signs in with it directly.
ALICE=$(api -X POST "$B/users" -d '{"username":"alice","display_name":"Alice","roles":["user"],"password":"alice passphrase 2026","must_change_password":false}' | jget 'd["user"]["id"] if "user" in d else d["id"]')
api -X PUT "$B/groups/$GRP/members" -d "{\"user_ids\":[\"$ROOT\",\"$ALICE\"]}" > /dev/null
CRED=$(api -X POST "$B/credentials" -d '{"name":"fake-pw","type":"password","mode":"vaulted","username":"test","password":"pw"}' | jget 'd["id"]')
TID=$(api -X POST "$B/targets" -d "{\"name\":\"fake-1\",\"address\":\"$LAN\",\"os_family\":\"linux\",\"ports\":{\"ssh\":$SSHPORT},\"tags\":{\"env\":\"test\"}}" | jget 'd["id"]')
api -X PUT "$B/targets/$TID/credentials/ssh" -d "{\"credential_id\":\"$CRED\"}" > /dev/null
FP=$(api -X POST "$B/targets/$TID/probe" | jget 'd["host_key_fingerprint"]')
api -X POST "$B/targets/$TID/host-key/trust" -d "{\"host_key_fingerprint\":\"$FP\"}" > /dev/null
api -X POST "$B/access-policies" -d "{\"name\":\"ops-test-ssh\",\"group_id\":\"$GRP\",\"target_selector\":{\"tags\":{\"env\":\"test\"}},\"protocols\":[\"ssh\"],\"idle_timeout_minutes\":15,\"require_mfa\":false}" > /dev/null
# The browser signs in on its own; the seeding sign-in is ended so it leaves no trace in what the tests see.
api -X POST "$B/auth/logout" > /dev/null || true

# A second gateway, in managed TLS mode, for the application test (ADR 0033):
# applications need an https public address and a certificate for the apps
# domain, which the plain-HTTP gateway above cannot give. The names
# console.test and *.apps.test exist nowhere; the browser maps them to the
# loopback address itself (Chromium host resolver rules), so the run needs
# no DNS, which is also how an operator without DNS runs applications. The
# wildcard certificate comes from a throwaway private CA made here.
T=$S/tls; mkdir -p "$T"
openssl ecparam -name prime256v1 -genkey -noout -out "$T/ca.key" 2>/dev/null
openssl req -x509 -new -key "$T/ca.key" -sha256 -days 2 -subj "/CN=e2e private CA" -out "$T/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$T/apps.key" 2>/dev/null
openssl req -new -key "$T/apps.key" -subj "/CN=*.apps.test" -out "$T/apps.csr" 2>/dev/null
printf 'subjectAltName=DNS:*.apps.test\nextendedKeyUsage=serverAuth\n' > "$T/apps.ext"
openssl x509 -req -in "$T/apps.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial -days 2 -sha256 -extfile "$T/apps.ext" -out "$T/apps.crt" 2>/dev/null
(
  export ZANSKAR_DB_DSN="file:$T/e2e-tls.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" ZANSKAR_LISTEN_ADDR=127.0.0.1:$TLSPORT ZANSKAR_RECORDINGS_DIR=$T/rec ZANSKAR_STATE_DIR=$T
  export ZANSKAR_TLS_MODE=managed ZANSKAR_TLS_HOSTS=console.test ZANSKAR_PUBLIC_URL="https://console.test:$TLSPORT" ZANSKAR_APPS_DOMAIN=apps.test
  ./bin/zanskar migrate >/dev/null 2>&1
  ZANSKAR_ADMIN_PASSWORD='bootstrap passphrase 2026' ./bin/zanskar admin create --username root --name "First Admin" >/dev/null
  ( ./bin/zanskar serve > "$S/gateway-tls.log" 2>&1 & )
)
for _ in $(seq 50); do curl -skf "https://127.0.0.1:$TLSPORT/readyz" >/dev/null && break; sleep 0.2; done
curl -skf "https://127.0.0.1:$TLSPORT/readyz" >/dev/null || { echo "the TLS gateway did not come up"; cat "$S/gateway-tls.log"; exit 1; }
B2=https://127.0.0.1:$TLSPORT/api/v1
J2=$S/jar-tls
login2=$(curl -sk -c "$J2" -X POST "$B2/auth/login" -H 'Content-Type: application/json' -d '{"username":"root","password":"bootstrap passphrase 2026"}')
CSRF2=$(echo "$login2" | jget 'd["csrf_token"]')
ROOT2=$(echo "$login2" | jget 'd["user"]["id"]')
api2() { curl -sk -b "$J2" -H "X-CSRF-Token: $CSRF2" -H 'Content-Type: application/json' "$@"; }
python3 -c "import json,sys; print(json.dumps({'cert_pem': open('$T/apps.crt').read(), 'key_pem': open('$T/apps.key').read()}))" > "$T/upload.json"
api2 -X PUT "$B2/admin/tls/apps" --data-binary "@$T/upload.json" > /dev/null
ALICE2=$(api2 -X POST "$B2/users" -d '{"username":"alice","display_name":"Alice","roles":["user"],"password":"alice passphrase 2026","must_change_password":false}' | jget 'd["user"]["id"] if "user" in d else d["id"]')
GRP2=$(api2 -X POST "$B2/groups" -d '{"name":"ops","description":"operators"}' | jget 'd["id"]')
api2 -X PUT "$B2/groups/$GRP2/members" -d "{\"user_ids\":[\"$ROOT2\",\"$ALICE2\"]}" > /dev/null
api2 -X POST "$B2/targets" -d "{\"name\":\"notes\",\"app_upstream\":\"http://$LAN:$HTTPPORT\",\"app_label\":\"notes\",\"tags\":{\"app\":\"test\"}}" > /dev/null
api2 -X POST "$B2/access-policies" -d "{\"name\":\"ops-apps\",\"group_id\":\"$GRP2\",\"target_selector\":{\"tags\":{\"app\":\"test\"}},\"protocols\":[\"http\"],\"idle_timeout_minutes\":15,\"require_mfa\":false}" > /dev/null
api2 -X POST "$B2/auth/logout" > /dev/null || true
export E2E_TLS_BASE_URL="https://console.test:$TLSPORT"

export E2E_BASE_URL="http://127.0.0.1:$PORT"
# The suite's exit code is kept, not acted on at once: the gateway's own
# errors are reported whichever way the browser run went, and the logs stay
# under $S for CI to upload when it fails.
status=0
(cd web && ./node_modules/.bin/playwright test --config e2e/playwright.config.ts "$@") || status=$?
# A gateway error during the run fails it even when every browser test
# passed: an error on each connect is a bug the suite would otherwise hide.
errors=$(cat "$S/gateway.log" "$S/gateway-tls.log" | grep -c 'level=ERROR' || true)
echo "gateway errors: $errors"; cat "$S/gateway.log" "$S/gateway-tls.log" | grep 'level=ERROR' | head -5 | cut -c1-200 || true
if [[ "$errors" != "0" && "$status" == "0" ]]; then echo "the browser suite passed but the gateway logged errors; failing"; status=1; fi
echo "logs: $S"
exit $status
