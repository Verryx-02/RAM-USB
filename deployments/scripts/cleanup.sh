#!/bin/bash
# Shell 12 (optional) - full cleanup. Add --wipe to also delete persisted
# data/mesh identities (everything re-joins as brand-new Headscale nodes
# next start - clean up orphaned nodes with `headscale nodes delete
# --identifier <id> --force` afterward).
#
# Uses `docker rm -f <container>` directly, NOT `docker compose down`:
# `down` re-interpolates the compose file, which fails closed on every
# `${VAR:?...}` credential even though their value is irrelevant to a
# teardown - `docker rm -f` needs no env vars at all.
#
# Headscale and Postgres are no longer separate containers (see
# network-manager.sh/database-vault.sh) - network-manager-headscale and
# database-vault-postgres are gone from this list, folded into
# network-manager/database-vault themselves.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

for c in grafana metrics-collector entry-hub security-switch network-manager \
         storage-service database-vault metrics-collector-timescaledb \
         mqtt-broker-mesh mqtt-broker certificate-authority-mesh certificate-authority \
         ramusb-tailscale-test; do
  docker rm -f "$c" >/dev/null 2>&1 || true
done
docker network rm ramusb-net 2>/dev/null || true

if [ "${1:-}" = "--wipe" ]; then
  docker volume rm \
    ramusb-database-vault_ramusb-postgres-data \
    ramusb-network-manager_ramusb-headscale-data \
    ramusb-certificate-authority_ramusb-ca-data \
    ramusb-metrics-collector-timescaledb_ramusb-metrics-collector-timescaledb-data \
    ramusb-grafana_ramusb-grafana-data \
    ramusb-security-switch_ramusb-security-switch-mesh-state \
    ramusb-database-vault_ramusb-database-vault-mesh-state \
    ramusb-network-manager_ramusb-network-manager-mesh-state \
    ramusb-storage-service_ramusb-storage-service-mesh-state \
    ramusb-certificate-authority_ramusb-certificate-authority-mesh-state \
    ramusb-mqtt-broker_ramusb-mqtt-broker-mesh-state \
    2>/dev/null || true
  echo "wiped. Also clean up the now-orphaned Headscale nodes (see Known issues #1 in MANUAL-DISTRIBUTED-RUN.md) once network-manager.sh is back up."
fi
