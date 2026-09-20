#!/bin/zsh
# End-to-end smoke test: admin sets up a target, user connects over SSH via WebSocket, recording and audit verified.
set -u
S=${SMOKE_TMP:-$(mktemp -d)}
cd /Users/aashish.gupta/Desktop/zanskar
LAN=$(ipconfig getifaddr en0)
# Only stop processes bound to the smoke ports, never a developer's own server on 8443/2222.
for port in 18443 2223; do lsof -ti tcp:$port 2>/dev/null | xargs kill 2>/dev/null; done; sleep 0.5
rm -rf $S/e2e.db $S/e2e.db-wal $S/e2e.db-shm $S/e2e-rec
( ./bin/fakessh 0.0.0.0:2223 > $S/fakessh.log 2>&1 & ); sleep 0.5
echo "fakessh: $(cat $S/fakessh.log)"
export ZANSKAR_DB_DSN="file:$S/e2e.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" ZANSKAR_LOG_FORMAT=text ZANSKAR_LISTEN_ADDR=127.0.0.1:18443 ZANSKAR_REQUIRE_MFA=false ZANSKAR_RECORDINGS_DIR=$S/e2e-rec
./bin/zanskar migrate >/dev/null 2>&1
ZANSKAR_ADMIN_PASSWORD='bootstrap passphrase 2026' ./bin/zanskar admin create --username root --name "First Admin" >/dev/null
export ZANSKAR_MASTER_KEY=$(./bin/zanskar keygen)
( ./bin/zanskar serve > $S/e2e.log 2>&1 & ); sleep 1
B=http://127.0.0.1:18443/api/v1
J=$S/e2e.jar
login=$(curl -s -c $J -X POST $B/auth/login -H 'Content-Type: application/json' -d '{"username":"root","password":"bootstrap passphrase 2026"}')
CSRF=$(echo $login | python3 -c 'import sys,json; print(json.load(sys.stdin)["csrf_token"])')
ROOT=$(echo $login | python3 -c 'import sys,json; print(json.load(sys.stdin)["user"]["id"])')
api() { curl -s -b $J -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

GRP=$(api -X POST $B/groups -d '{"name":"ops","description":"operators"}' | jget 'd["id"]')
api -X PUT $B/groups/$GRP/members -d "{\"user_ids\":[\"$ROOT\"]}" > /dev/null
CRED=$(api -X POST $B/credentials -d '{"name":"fake-pw","type":"password","mode":"vaulted","username":"test","password":"pw"}' | jget 'd["id"]')
echo "credential json has secret fields: $(api $B/credentials/$CRED | grep -c '"password"')"
TID=$(api -X POST $B/targets -d "{\"name\":\"fake-1\",\"address\":\"$LAN\",\"os_family\":\"linux\",\"ports\":{\"ssh\":2223},\"tags\":{\"env\":\"test\"}}" | jget 'd["id"]')
api -X PUT $B/targets/$TID/credentials/ssh -d "{\"credential_id\":\"$CRED\"}" > /dev/null
probe=$(api -X POST $B/targets/$TID/probe)
echo "probe: $(echo $probe | jget '"status=%s caps=%s fp=%s" % (d["host_key_status"], d["target"]["capabilities"], d["host_key_fingerprint"])')"
FP=$(echo $probe | jget 'd["host_key_fingerprint"]')
echo "connect before trust: $(api -X POST $B/connect -d "{\"target_id\":\"$TID\",\"protocol\":\"ssh\"}" | jget 'd["code"]')"
echo "trust: $(api -X POST $B/targets/$TID/host-key/trust -d "{\"host_key_fingerprint\":\"$FP\"}" | jget 'd["host_key_status"]')"
echo "connect before policy: $(api -X POST $B/connect -d "{\"target_id\":\"$TID\",\"protocol\":\"ssh\"}" | jget 'd["code"]')"
api -X POST $B/access-policies -d "{\"name\":\"ops-test-ssh\",\"group_id\":\"$GRP\",\"target_selector\":{\"tags\":{\"env\":\"test\"}},\"protocols\":[\"ssh\"],\"idle_timeout_minutes\":15,\"require_mfa\":false}" > /dev/null
echo "me/targets: $(api $B/me/targets | jget '[(t["name"], t["allowed_protocols"], t["host_key_ready"]) for t in d["items"]]')"
TICKET=$(api -X POST $B/connect -d "{\"target_id\":\"$TID\",\"protocol\":\"ssh\"}" | jget 'd["ticket"]')
echo "ticket length: ${#TICKET}"
./bin/wsclient "ws://127.0.0.1:18443/ws/terminal?ticket=$TICKET&cols=80&rows=24"
echo "ticket reuse: $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:18443/ws/terminal?ticket=$TICKET")"
sess=$(api "$B/sessions?limit=5")
echo "sessions: $(echo $sess | jget '[(s["protocol"], s["end_reason"], bool(s["recording_id"])) for s in d["items"]]')"
RID=$(echo $sess | jget 'd["items"][0]["recording_id"]')
api $B/recordings/$RID/stream > $S/e2e.cast
echo "recording: $(head -c 120 $S/e2e.cast | tr -d '\n') ... lines=$(wc -l < $S/e2e.cast) contains HELLO: $(grep -c HELLO $S/e2e.cast)"
echo "recording views audited: $(api "$B/audit/events?action=recording.view" | jget 'len(d["items"])')"
echo "my sessions hide recording id: $(api $B/me/sessions | grep -c recording_id)"
echo "spa /: $(curl -s -o /dev/null -w '%{http_code} %{content_type}' http://127.0.0.1:18443/)  /admin/targets: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18443/admin/targets)  title: $(curl -s http://127.0.0.1:18443/login | grep -o '<title>[^<]*')"
echo "spa csp: $(curl -s -D - -o /dev/null http://127.0.0.1:18443/ | grep -i content-security | cut -c1-70)"
echo "asset cache: $(curl -s -D - -o /dev/null http://127.0.0.1:18443$(curl -s http://127.0.0.1:18443/ | grep -o '/assets/index-[^"]*\.js' | head -1) | grep -i cache-control)"
for port in 18443 2223; do lsof -ti tcp:$port 2>/dev/null | xargs kill 2>/dev/null; done; sleep 1
echo "audit verify: $(./bin/zanskar audit verify 2>&1 | cut -c1-60)"
echo "server errors: $(grep -c 'level=ERROR' $S/e2e.log)"; grep 'level=ERROR' $S/e2e.log | head -3 | cut -c1-200
