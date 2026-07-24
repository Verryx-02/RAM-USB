#!/bin/bash
# Shell 3 - Network-Manager (+ mesh, real tailscaled). Requires shells 1
# (Certificate-Authority) and 2 (Headscale, standalone).
#
# This session's architectural change removed the old two-phase startup
# entirely: that was only needed because Headscale used to be co-located
# inside this same container (its API key could only be minted by
# `docker exec`-ing into an already-running network-manager container,
# which Compose needed the value of before it could even create). Now
# that Headscale is its own already-running container (shell 2), its API
# key and Network-Manager's own mesh pre-auth key can both be minted
# BEFORE this container is ever created - same single-pass shape as every
# other mesh-joined service's own script (security-switch.sh,
# database-vault.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

echo ">>> waiting for Headscale to be reachable..."
until docker exec headscale curl -fsS http://127.0.0.1:8081/health >/dev/null 2>&1; do
  sleep 1
done

docker exec headscale headscale users create network-manager 2>/dev/null || true
NM_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="network-manager") | .id')

export RAM_USB_NETWORK_MANAGER_HEADSCALE_API_KEY=$(docker exec headscale headscale apikeys create --expiration 24h)

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token NetworkManager \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$NM_ID" --expiration 30m --tags tag:network-manager)

docker compose -f deployments/compose/network-manager.yml up --build
