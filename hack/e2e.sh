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
stop() { for port in "$PORT" "$SSHPORT"; do lsof -ti "tcp:$port" 2>/dev/null | xargs kill 2>/dev/null || true; done; }
stop; sleep 0.5
trap stop EXIT
rm -rf "$S/e2e.db" "$S/e2e.db-wal" "$S/e2e.db-shm" "$S/rec" "$S/jar"

( ./bin/fakessh "0.0.0.0:$SSHPORT" > "$S/fakessh.log" 2>&1 & )
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

export E2E_BASE_URL="http://127.0.0.1:$PORT"
# The suite's exit code is kept, not acted on at once: the gateway's own
# errors are reported whichever way the browser run went, and the logs stay
# under $S for CI to upload when it fails.
status=0
(cd web && ./node_modules/.bin/playwright test --config e2e/playwright.config.ts "$@") || status=$?
# A gateway error during the run fails it even when every browser test
# passed: an error on each connect is a bug the suite would otherwise hide.
errors=$(grep -c 'level=ERROR' "$S/gateway.log" || true)
echo "gateway errors: $errors"; grep 'level=ERROR' "$S/gateway.log" | head -5 | cut -c1-200 || true
if [[ "$errors" != "0" && "$status" == "0" ]]; then echo "the browser suite passed but the gateway logged errors; failing"; status=1; fi
echo "logs: $S"
exit $status
