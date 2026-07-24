#!/bin/bash
# Shell 4 - MQTT-Broker + its Tailscale mesh sidecar. Requires shells 1, 2.
# Certs are dev-only (~24h validity, minted via the CA's admin API, not
# CA-F-04's bootstrap-token flow - see RISK-04 in the SRS for why this
# is not production-ready). Regenerated automatically here if missing;
# re-run this script manually if MQTT starts failing on an expired cert.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

[ -f third-party/mosquitto/certs/broker.dev-only.crt ] || third-party/mosquitto/generate-dev-certs.sh certificate-authority

docker exec headscale headscale users create mqtt-broker 2>/dev/null || true
MQTT_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="mqtt-broker") | .id')
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_MQTT_BROKER_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$MQTT_ID" --expiration 30m --tags tag:mqtt-broker)

docker compose -f deployments/compose/mqtt-broker.yml up
