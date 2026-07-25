#!/bin/bash
# Shell 13 (optional) - full cleanup. Add --wipe to also delete persisted
# data/mesh identities (everything re-joins as brand-new Headscale nodes
# next start - clean up orphaned nodes with `headscale nodes delete
# --identifier <id> --force` afterward).
#
# Uses `docker rm -f <container>` directly, NOT `docker compose down`:
# `down` re-interpolates the compose file, which fails closed on every
# `${VAR:?...}` credential even though their value is irrelevant to a
# teardown - `docker rm -f` needs no env vars at all.
#
# Postgres is no longer a separate container (see database-vault.sh) -
# database-vault-postgres is gone from this list, folded into
# database-vault itself. Headscale, by contrast, is its OWN standalone
# container again this session (see headscale.sh/network-manager.sh) -
# added back to this list under its own name. TimescaleDB is likewise no
# longer a separate container (see metrics-collector.sh, KI-18) -
# metrics-collector-timescaledb is gone from this list, folded into
# metrics-collector itself.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

for c in grafana metrics-collector entry-hub security-switch network-manager \
         storage-service database-vault \
         mqtt-broker-mesh mqtt-broker certificate-authority-mesh certificate-authority \
         headscale ramusb-tailscale-test; do
  docker rm -f "$c" >/dev/null 2>&1 || true
done
docker network rm ramusb-net 2>/dev/null || true

if [ "${1:-}" = "--wipe" ]; then
  docker volume rm \
    ramusb-database-vault_ramusb-postgres-data \
    ramusb-headscale_ramusb-headscale-data \
    ramusb-certificate-authority_ramusb-ca-data \
    ramusb-metrics-collector_ramusb-metrics-collector-timescaledb-data \
    ramusb-metrics-collector_ramusb-metrics-collector-mesh-state \
    ramusb-grafana_ramusb-grafana-data \
    ramusb-security-switch_ramusb-security-switch-mesh-state \
    ramusb-database-vault_ramusb-database-vault-mesh-state \
    ramusb-network-manager_ramusb-network-manager-tailscale-state \
    ramusb-storage-service_ramusb-storage-service-mesh-state \
    ramusb-certificate-authority_ramusb-certificate-authority-mesh-state \
    ramusb-mqtt-broker_ramusb-mqtt-broker-mesh-state \
    2>/dev/null || true
  echo "wiped. Also clean up the now-orphaned Headscale nodes (see Known issues #1 in MANUAL-DISTRIBUTED-RUN.md) once headscale.sh is back up."
fi
