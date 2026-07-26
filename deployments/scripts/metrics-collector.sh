#!/bin/bash
# Shell 6 - Metrics-Collector, now co-located with its own TimescaleDB in
# one container (MT-F-03, docs/Known_Issues.md's KI-18) - no separate
# metrics-collector-timescaledb.sh anymore, no cross-shell password
# handoff (this is the only place the password is generated). Requires
# shells 1, 2, 4.
#
# RAM_USB_METRICS_COLLECTOR_TIMESCALEDB_BOOTSTRAP_TOKEN (KI-22, PKI-F-03):
# a SEPARATE CA-F-04 bootstrap token from RAM_USB_CA_BOOTSTRAP_TOKEN above
# - that one is consumed in-process by the Go binary itself
# (pki.NewClient, MQTT identity "MetricsCollector"); this one is consumed
# by metrics-collector-timescaledb-cert-issuer for TimescaleDB's own,
# separate server identity "MetricsCollectorTimescaleDB"
# (deployments/compose/metrics-collector.yml).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"

docker exec headscale headscale users create metrics-collector 2>/dev/null || true
MC_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="metrics-collector") | .id')

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token MetricsCollector \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_METRICS_COLLECTOR_TIMESCALEDB_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token MetricsCollectorTimescaleDB \
  --san MetricsCollectorTimescaleDB --san metrics-collector --san localhost --san 127.0.0.1 \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$MC_ID" --expiration 30m --tags tag:metrics-collector)

docker compose -f deployments/compose/metrics-collector.yml up --build
