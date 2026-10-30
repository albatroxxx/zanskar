#!/bin/sh
# Runs in the scripted browser's container (hack/keycloak/run.sh): the gateway
# on loopback, trusting the throwaway Keycloak certificate, then the checks.
set -e
cd /tmp
export SSL_CERT_FILE=/work/kc.pem ZANSKAR_DB_DSN="file:/tmp/z.db?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" ZANSKAR_LOG_FORMAT=text
export ZANSKAR_LISTEN_ADDR=127.0.0.1:18443 ZANSKAR_REQUIRE_MFA=true ZANSKAR_RECORDINGS_DIR=/tmp/rec ZANSKAR_TLS_MODE= ZANSKAR_MASTER_KEY_FILE= ZANSKAR_STATE_DIR=/tmp/state
cp /work/zanskar /tmp/zanskar && chmod +x /tmp/zanskar
/tmp/zanskar migrate >/dev/null 2>&1
ZANSKAR_E2E_ROOT_PW=$(head -c 18 /dev/urandom | base64); export ZANSKAR_E2E_ROOT_PW
ZANSKAR_ADMIN_PASSWORD=$ZANSKAR_E2E_ROOT_PW /tmp/zanskar admin create --username root --name "First Admin" >/dev/null 2>&1
ZANSKAR_MASTER_KEY=$(/tmp/zanskar keygen); export ZANSKAR_MASTER_KEY
/tmp/zanskar serve > /tmp/z.log 2>&1 &
for _ in $(seq 1 50); do wget -q -O /dev/null http://127.0.0.1:18443/readyz 2>/dev/null && break; sleep 0.2; done
python3 /work/e2e.py || { echo "--- gateway log"; tail -40 /tmp/z.log; exit 1; }
errors=$(grep -c "level=ERROR" /tmp/z.log || true)
echo "gateway errors: $errors"
[ "$errors" = 0 ] || { grep "level=ERROR" /tmp/z.log; exit 1; }
