#!/bin/bash
# Shell 1 - Network-Manager, now co-located with its own Headscale mesh
# backend in one container (NM-F-14) - no separate headscale.sh anymore.
#
# Two-phase startup, unavoidable now that Headscale lives inside this same
# container: the API key/pre-auth key below can only be minted by `docker
# exec` into an ALREADY-RUNNING container, but Compose needs their value
# BEFORE it can create that container in the first place. Phase 1 starts
# the container with placeholder secrets (network-manager's own Go process
# will fail/retry harmlessly until phase 2 - its co-located Headscale
# starts and serves regardless, s6-overlay supervises them independently).
# Phase 2 mints the real secrets via `docker exec` now that Headscale is
# up, then re-runs `up` so Compose recreates the container with them.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

# --- phase 1: get the co-located Headscale serving ---
export RAM_USB_HEADSCALE_API_KEY="bootstrap-placeholder"
export RAM_USB_CA_BOOTSTRAP_TOKEN="bootstrap-placeholder"
export RAM_USB_TAILSCALE_CONTROL_URL="https://localhost:8080"
export RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY="bootstrap-placeholder"
docker compose -f deployments/compose/network-manager.yml up -d --build

echo ">>> waiting for the co-located Headscale to become healthy..."
until docker exec network-manager /usr/local/bin/headscale health >/dev/null 2>&1; do sleep 1; done

# --- phase 2: mint the real secrets now that Headscale is reachable ---
docker exec network-manager headscale users create network-manager 2>/dev/null || true
NM_ID=$(docker exec network-manager headscale users list -o json | jq -r '.[] | select(.name=="network-manager") | .id')

export RAM_USB_HEADSCALE_API_KEY=$(docker exec network-manager headscale apikeys create --expiration 24h)

# Certificate-Authority may still be starting in its own shell (there is no
# ordering requirement between that shell and this one anymore, unlike the
# old headscale.sh which everything else waited on) - retry until its
# step-ca server answers rather than failing once.
echo ">>> waiting for Certificate-Authority to be reachable for CA-token minting..."
RAM_USB_CA_BOOTSTRAP_TOKEN=""
until [ -n "$RAM_USB_CA_BOOTSTRAP_TOKEN" ]; do
  RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token NetworkManager \
    --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
    --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null) || true
  [ -z "$RAM_USB_CA_BOOTSTRAP_TOKEN" ] && sleep 1
done
export RAM_USB_CA_BOOTSTRAP_TOKEN
export RAM_USB_TAILSCALE_CONTROL_URL="https://localhost:8080"
export RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY=$(docker exec network-manager headscale preauthkeys create --user "$NM_ID" --expiration 30m --tags tag:network-manager)

# recreate with the real secrets - foreground from here on
docker compose -f deployments/compose/network-manager.yml up --build
