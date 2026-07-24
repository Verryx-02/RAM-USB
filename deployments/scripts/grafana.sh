#!/bin/bash
# Shell 11 - Grafana. Requires shell 5 (metrics-collector-timescaledb.sh)
# already running.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

export RAM_USB_GRAFANA_ADMIN_USER="admin"
export RAM_USB_GRAFANA_ADMIN_PASSWORD="dev-only-pw-$(openssl rand -hex 8)"
echo ">>> Grafana admin password (http://localhost:3000, user admin): $RAM_USB_GRAFANA_ADMIN_PASSWORD"

docker compose -f deployments/compose/grafana.yml up
