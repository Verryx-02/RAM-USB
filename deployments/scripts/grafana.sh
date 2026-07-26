#!/bin/bash
# Shell 11 - Grafana. Requires shell 6 (metrics-collector.sh, which now
# co-locates TimescaleDB - KI-18) already running.
#
# RAM_USB_GRAFANA_TIMESCALEDB_BOOTSTRAP_TOKEN (KI-22, PKI-F-03): Grafana's
# own mTLS CLIENT identity for its TimescaleDB connection
# (deployments/compose/grafana.yml's grafana-cert-issuer). Minted with
# subject "metrics_collector" - EXACTLY the Postgres role Grafana connects
# as - because TimescaleDB's `clientcert=verify-full` pg_hba.conf rule
# requires the two to match exactly (third-party/timescaledb/
# pg_hba-mtls.sh).
#
# RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD: queried from the
# already-running metrics-collector container rather than re-derived -
# metrics-collector.sh generates it randomly and is the sole source of
# truth for its current value (compose-convention.md's cross-project
# shared-secret pattern).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

export RAM_USB_GRAFANA_ADMIN_USER="admin"
export RAM_USB_GRAFANA_ADMIN_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
echo ">>> Grafana admin password (http://localhost:3000, user admin): $RAM_USB_GRAFANA_ADMIN_PASSWORD"

export RAM_USB_GRAFANA_TIMESCALEDB_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token metrics_collector \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD=$(docker exec metrics-collector printenv POSTGRES_PASSWORD)

docker compose -f deployments/compose/grafana.yml up
