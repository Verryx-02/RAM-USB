#!/bin/bash
# Shell 11 - end-to-end test: register, real client mesh join, login, verify.
# Run only once shells 1-10 are all up and quiet.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

rm -f /tmp/ramusb_test_key /tmp/ramusb_test_key.pub
ssh-keygen -t ed25519 -N "" -f /tmp/ramusb_test_key -C "test@ramusb" -q
TESTKEY=$(cat /tmp/ramusb_test_key.pub)
TESTEMAIL="test-$(date +%s)@example.com"

REGISTER_RAW=$(curl -sk -w "\n%{http_code}" -X POST https://localhost:8443/api/register \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF
{"email":"$TESTEMAIL","password":"Sup3rSecretPass123","ssh_public_key":"$TESTKEY"}
EOF
)
echo "$REGISTER_RAW"
REGISTER_BODY=$(echo "$REGISTER_RAW" | sed '$d')
PREAUTHKEY=$(echo "$REGISTER_BODY" | grep -o '"pre_auth_key":"[^"]*"' | cut -d'"' -f4)
[ -z "$PREAUTHKEY" ] && { echo "ERROR: no pre_auth_key in response, check entry-hub/security-switch logs" >&2; exit 1; }

# client joins the mesh with the key just issued - login below needs this
export TS_AUTHKEY="$PREAUTHKEY"
docker compose -f deployments/compose/tailscale-test.yml up -d --force-recreate
sleep 6
docker logs ramusb-tailscale-test 2>&1 | tail -5

# login MUST come after the mesh join above, or it 403s by design (RD-04) -
# NM's SS-F-05 grant looks up the client's mesh node by pre-auth-key ID
curl -sk -X POST https://localhost:8443/api/login \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF -w "\nHTTP_STATUS:%{http_code}\n"
{"email":"$TESTEMAIL","password":"Sup3rSecretPass123"}
EOF

# Postgres now lives inside the database-vault container itself (loopback
# only) - psql runs there via docker exec, not against a separate
# database-vault-postgres container anymore.
docker exec database-vault psql -U database_vault -d database_vault \
  -c "SELECT posix_username, registered_at FROM users ORDER BY registered_at DESC LIMIT 5;"
# Headscale now lives inside the network-manager container itself.
docker exec network-manager headscale nodes list

echo "waiting 65s for metrics to publish (EH-F-10/SS-F-07/etc. publish every 60s)..."
sleep 65
docker exec metrics-collector-timescaledb psql -U metrics_collector -d metrics_collector \
  -c "SELECT service, time, request_count, error_count, average_response_time_ms, active_connections FROM metrics ORDER BY time DESC LIMIT 5;"
