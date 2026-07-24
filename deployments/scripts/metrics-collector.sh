#!/bin/bash
# Shell 10 - Metrics-Collector. Not a mesh node, reaches mqtt-broker over
# ramusb-net. Requires shell 5 (metrics-collector-timescaledb.sh) already
# running.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

read -rp "TimescaleDB password (from metrics-collector-timescaledb.sh): " RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD
export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token MetricsCollector \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/metrics-collector.yml up --build
