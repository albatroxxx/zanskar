#!/usr/bin/env bash
# Starts a throwaway gateway with fakessh and seeds it, through the API, with
# the fictional organisation the site's screenshots show. Prints the session
# cookies shoot.mjs needs. Run from the repository root after building
# bin/zanskar with the console (-tags webui) and bin/fakessh.
set -euo pipefail

DIR=${SHOT_DIR:-$(mktemp -d)}
PORT=${SHOT_PORT:-18543}
SSH_PORT=${SHOT_SSH_PORT:-2232}
LAN=${SHOT_LAN_IP:-$(ipconfig getifaddr en0 2>/dev/null || hostname -I | awk '{print $1}')}
B="http://127.0.0.1:$PORT/api/v1"

for p in "$PORT" "$SSH_PORT"; do lsof -ti "tcp:$p" 2>/dev/null | xargs kill 2>/dev/null || true; done
sleep 0.5
rm -rf "$DIR/shots.db"* "$DIR/rec"

export ZANSKAR_DB_DSN="file:$DIR/shots.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
export ZANSKAR_LISTEN_ADDR=127.0.0.1:$PORT ZANSKAR_REQUIRE_MFA=false ZANSKAR_RECORDINGS_DIR=$DIR/rec ZANSKAR_LOG_FORMAT=text
export ZANSKAR_MASTER_KEY_FILE= ZANSKAR_TLS_MODE=
./bin/zanskar migrate >/dev/null 2>&1
ZANSKAR_ADMIN_PASSWORD='screenshot admin passphrase' ./bin/zanskar admin create --username admin --name "Priya Nair" >/dev/null # gitleaks:allow -- a made-up account on a throwaway gateway
export ZANSKAR_MASTER_KEY=$(./bin/zanskar keygen)
(./bin/zanskar serve >"$DIR/serve.log" 2>&1 &)
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/readyz" >/dev/null && break; sleep 0.2; done

jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
login() { curl -s -c "$DIR/$1.jar" -X POST "$B/auth/login" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
CSRF=$(login admin 'screenshot admin passphrase' | jget 'd["csrf_token"]')
api() { curl -s -b "$DIR/admin.jar" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
id() { jget 'd.get("id") or d'; }

# The admin enrols an authenticator, so the console's command line opens.
totp() { python3 -c 'import base64,hmac,struct,sys,time
k=base64.b32decode(sys.argv[1]+"="*(-len(sys.argv[1])%8)); h=hmac.digest(k,struct.pack(">Q",int(time.time())//30),"sha1")
o=h[-1]&15; print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "$1"; }
SECRET=$(api -X POST "$B/auth/mfa/totp/enroll" | jget 'd["secret"]')
CSRF=$(api -X POST "$B/auth/mfa/totp/confirm" -d "{\"code\":\"$(totp "$SECRET")\"}" | jget 'd["csrf_token"]')
# Open it now, so its audit event sits below the ones the Events shot shows;
# it stays open for 15 idle minutes, far longer than the shots take. A code
# works once, so wait for the authenticator's next one.
sleep $((30 - $(date +%s) % 30 + 1))
api -X POST "$B/admin/cli/unlock" -d "{\"code\":\"$(totp "$SECRET")\"}" >/dev/null

# People and groups.
ALICE=$(api -X POST "$B/users" -d '{"username":"alice","display_name":"Alice Moreau","password":"alice temporary pw 1","roles":["user"]}' | id)
CAROL=$(api -X POST "$B/users" -d '{"username":"carol","display_name":"Carol Diaz","password":"carol temporary pw 1","roles":["user"]}' | id)
OPS=$(api -X POST "$B/groups" -d '{"name":"platform-ops","description":"Runs the web tier and bastions"}' | id)
DBA=$(api -X POST "$B/groups" -d '{"name":"dba","description":"Database administrators"}' | id)
api -X PUT "$B/groups/$OPS/members" -d "{\"user_ids\":[\"$ALICE\"]}" >/dev/null
api -X PUT "$B/groups/$DBA/members" -d "{\"user_ids\":[\"$ALICE\",\"$CAROL\"]}" >/dev/null

# Credentials, including the SSH certificate authority fakessh trusts.
pw() { api -X POST "$B/credentials" -d "{\"name\":\"$1\",\"type\":\"password\",\"mode\":\"vaulted\",\"username\":\"$2\",\"password\":\"fictional-$1-pw\"}" | id; }
BASTION_CRED=$(pw bastion-ops ops)
BILLING_CRED=$(pw billing-dba dba)
ORDERS_CRED=$(pw orders-readwrite app)
WIN_CRED=$(pw win-app-admin Administrator)
CA_JSON=$(api -X POST "$B/credentials" -d '{"name":"linux-fleet-ca","type":"ssh_ca","mode":"vaulted"}')
CA=$(echo "$CA_JSON" | id)
echo "$CA_JSON" | jget 'd["public_key"]' >"$DIR/ca.pub"
(./bin/fakessh -ca-pub "$DIR/ca.pub" -hostkey "$DIR/hostkey" "0.0.0.0:$SSH_PORT" >"$DIR/fakessh.log" 2>&1 &)
sleep 0.5

# Hosts: two fakessh-backed web servers probed and trusted, two never probed.
host() { api -X POST "$B/targets" -d "$1" | id; }
BASTION=$(host "{\"name\":\"bastion-eu1\",\"address\":\"10.20.4.10\",\"os_family\":\"linux\",\"tags\":{\"env\":\"prod\",\"role\":\"bastion\"},\"credentials\":{\"ssh\":\"$BASTION_CRED\"}}")
for n in web-01 web-02; do
  T=$(host "{\"name\":\"$n\",\"address\":\"$LAN\",\"os_family\":\"linux\",\"ports\":{\"ssh\":$SSH_PORT},\"tags\":{\"env\":\"staging\",\"role\":\"web\"},\"credentials\":{\"ssh\":\"$CA\"}}")
  FP=$(api -X POST "$B/targets/$T/probe" | jget 'd["host_key_fingerprint"]')
  api -X POST "$B/targets/$T/host-key/trust" -d "{\"host_key_fingerprint\":\"$FP\"}" >/dev/null
done
host "{\"name\":\"win-app-01\",\"address\":\"10.20.8.21\",\"os_family\":\"windows\",\"tags\":{\"env\":\"prod\",\"role\":\"app\"},\"credentials\":{\"rdp\":\"$WIN_CRED\",\"winrm\":\"$WIN_CRED\"}}" >/dev/null

# Databases: one verified (RDS-style, with a CA bundle), one encrypted but unverified.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=Fictional Screenshot CA" \
  -keyout "$DIR/db-ca.key" -out "$DIR/db-ca.pem" >/dev/null 2>&1
CA_PEM=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$DIR/db-ca.pem")
ORDERS=$(host "{\"name\":\"orders-db\",\"address\":\"orders.c7xk2.eu-west-2.rds.amazonaws.com\",\"os_family\":\"linux\",\"engine\":\"postgres\",\"engine_version\":\"16\",\"database_name\":\"orders\",\"tls_mode\":\"verify-full\",\"tls_ca\":$CA_PEM,\"ports\":{\"database\":5432},\"tags\":{\"env\":\"prod\",\"role\":\"db\"},\"credentials\":{\"database\":\"$ORDERS_CRED\"}}")
BILLING=$(host "{\"name\":\"billing-db\",\"address\":\"billing.internal.example\",\"os_family\":\"linux\",\"engine\":\"mysql\",\"engine_version\":\"8.4\",\"database_name\":\"billing\",\"tls_mode\":\"require\",\"ports\":{\"database\":3306},\"tags\":{\"env\":\"prod\",\"role\":\"db\"},\"credentials\":{\"database\":\"$BILLING_CRED\"}}")

# Policies: standing SSH to staging, approval-gated bastion and databases.
pol() { api -X POST "$B/access-policies" -d "$1" >/dev/null; }
pol "{\"name\":\"ops-staging-ssh\",\"description\":\"Standing SSH to the staging web tier\",\"group_id\":\"$OPS\",\"target_selector\":{\"tags\":{\"env\":\"staging\"}},\"protocols\":[\"ssh\"],\"idle_timeout_minutes\":15,\"max_session_minutes\":240,\"require_mfa\":false}"
pol "{\"name\":\"prod-bastion-jit\",\"description\":\"Approval-gated production bastion\",\"group_id\":\"$OPS\",\"target_selector\":{\"tags\":{\"role\":\"bastion\"}},\"protocols\":[\"ssh\"],\"idle_timeout_minutes\":15,\"max_session_minutes\":120,\"require_approval\":true,\"require_mfa\":false}"
pol "{\"name\":\"prod-db-jit\",\"description\":\"Approval-gated production database access\",\"group_id\":\"$DBA\",\"target_selector\":{\"tags\":{\"role\":\"db\"}},\"protocols\":[\"database\"],\"idle_timeout_minutes\":10,\"max_session_minutes\":60,\"require_approval\":true,\"require_mfa\":false}"

# Users replace their first password, then ask for access.
as_user() { # name first-pw new-pw -> sets USER_CSRF and cookie jar
  local c
  c=$(login "$1" "$2" | jget 'd["csrf_token"]')
  curl -s -b "$DIR/$1.jar" -c "$DIR/$1.jar" -H "X-CSRF-Token: $c" -H 'Content-Type: application/json' -X POST "$B/auth/password" \
    -d "{\"current_password\":\"$2\",\"new_password\":\"$3\"}" >/dev/null
  USER_CSRF=$(login "$1" "$3" | jget 'd["csrf_token"]')
}
ask() { curl -s -b "$DIR/$1.jar" -H "X-CSRF-Token: $USER_CSRF" -H 'Content-Type: application/json' -X POST "$B/me/access-requests" -d "$2" | id; }
as_user carol 'carol temporary pw 1' 'carol chose this passphrase'
GRANT=$(ask carol "{\"target_id\":\"$BILLING\",\"protocol\":\"database\",\"reason\":\"Month-end reconciliation\",\"minutes\":60}")
api -X POST "$B/access-requests/$GRANT/approve" -d '{"note":"ok for month-end"}' >/dev/null
as_user alice 'alice temporary pw 1' 'alice chose this passphrase'
ask alice "{\"target_id\":\"$ORDERS\",\"protocol\":\"database\",\"reason\":\"INC-4821: investigate slow order lookups on the primary\",\"minutes\":60}" >/dev/null
ask alice "{\"target_id\":\"$BASTION\",\"protocol\":\"ssh\",\"reason\":\"Rotate the bastion's authorized_keys after the on-call handover\",\"minutes\":45}" >/dev/null

cookie() { awk '$6=="zanskar_session"{print $7}' "$DIR/$1.jar"; }
echo "BASE=http://127.0.0.1:$PORT"
echo "ADMIN_COOKIE=$(cookie admin)"
echo "ALICE_COOKIE=$(cookie alice)"
