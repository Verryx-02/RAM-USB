#!/bin/bash
# Shell 4 - TimescaleDB (Metrics-Collector's data).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

export RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
echo ">>> paste into metrics-collector.sh when asked: $RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD"

docker compose -f deployments/compose/metrics-collector-timescaledb.yml up
