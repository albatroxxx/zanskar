#!/bin/sh
# In the scripted browser's container, reachable on the network as "zk":
# the gateway on plain HTTP (a private test network), then the checks.
set -e
cd /tmp
export SSL_CERT_FILE=/w/ak.pem ZANSKAR_DB_DSN="file:/tmp/z.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" ZANSKAR_LOG_FORMAT=text
export ZANSKAR_LISTEN_ADDR=0.0.0.0:18443 ZANSKAR_ALLOW_PLAIN_HTTP=true ZANSKAR_REQUIRE_MFA=true ZANSKAR_RECORDINGS_DIR=/tmp/rec ZANSKAR_TLS_MODE= ZANSKAR_MASTER_KEY_FILE= ZANSKAR_STATE_DIR=/tmp/state
cp /w/zanskar /tmp/zanskar && chmod +x /tmp/zanskar
/tmp/zanskar migrate >/dev/null 2>&1
ZANSKAR_E2E_ROOT_PW=$(head -c 18 /dev/urandom | base64); export ZANSKAR_E2E_ROOT_PW
ZANSKAR_ADMIN_PASSWORD=$ZANSKAR_E2E_ROOT_PW /tmp/zanskar admin create --username root --name "First Admin" >/dev/null 2>&1
ZANSKAR_MASTER_KEY=$(/tmp/zanskar keygen); export ZANSKAR_MASTER_KEY
/tmp/zanskar serve > /tmp/z.log 2>&1 &
for _ in $(seq 1 50); do wget -q -O /dev/null http://127.0.0.1:18443/readyz 2>/dev/null && break; sleep 0.2; done
python3 /w/e2e.py || { echo "--- gateway log"; grep -v "path=/readyz" /tmp/z.log | tail -40; exit 1; }
errors=$(grep -c "level=ERROR" /tmp/z.log || true)
echo "gateway errors: $errors"
[ "$errors" = 0 ] || { grep "level=ERROR" /tmp/z.log; exit 1; }
