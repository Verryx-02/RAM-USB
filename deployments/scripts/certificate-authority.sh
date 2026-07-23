#!/bin/bash
# Shell 2 - Certificate-Authority + its Tailscale mesh sidecar (NM-F-04).
# Requires network-manager.sh already through its first phase (its
# co-located Headscale healthy) - see that script's own comment.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec network-manager headscale users create certificate-authority 2>/dev/null || true
CA_ID=$(docker exec network-manager headscale users list -o json | jq -r '.[] | select(.name=="certificate-authority") | .id')
export RAM_USB_TAILSCALE_CONTROL_URL="https://network-manager:8080"
export RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY=$(docker exec network-manager headscale preauthkeys create --user "$CA_ID" --expiration 30m --tags tag:certificate-authority)

docker compose -f deployments/compose/certificate-authority.yml up
