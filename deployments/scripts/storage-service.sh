#!/bin/bash
# Shell 7 - Storage-Service (+ real Tailscale client, not pkg/mesh, because
# it also runs sshd). SFTP is reachable only via mesh, no host port.
# Requires shells 1, 2.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec headscale headscale users create storage-service 2>/dev/null || true
ST_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="storage-service") | .id')

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token StorageService \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$ST_ID" --expiration 30m --tags tag:storage-service)

docker compose -f deployments/compose/storage-service.yml up --build
