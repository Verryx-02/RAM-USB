#!/bin/bash
# Shell 7 - Security-Switch (+ mesh). Requires shells 1, 2.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec network-manager headscale users create security-switch 2>/dev/null || true
SS_ID=$(docker exec network-manager headscale users list -o json | jq -r '.[] | select(.name=="security-switch") | .id')

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token SecuritySwitch \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://network-manager:8080"
export RAM_USB_SECURITY_SWITCH_TAILSCALE_AUTHKEY=$(docker exec network-manager headscale preauthkeys create --user "$SS_ID" --expiration 30m --tags tag:security-switch)

docker compose -f deployments/compose/security-switch.yml up --build
