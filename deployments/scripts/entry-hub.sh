#!/bin/bash
# Shell 9 - Entry-Hub (+ mesh, via pkg/mesh's in-process tsnet). Requires
# shells 1, 2, 4.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

[ -f third-party/entry-hub/config/server.dev-only.crt ] || third-party/entry-hub/generate-dev-cert.sh

docker exec headscale headscale users create entry-hub 2>/dev/null || true
EH_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="entry-hub") | .id')

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token EntryHub \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_ENTRY_HUB_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$EH_ID" --expiration 30m --tags tag:entry-hub)

docker compose -f deployments/compose/entry-hub.yml up --build
