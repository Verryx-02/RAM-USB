#!/bin/bash
# Shell 8 - Entry-Hub. Not a mesh node, unchanged.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

[ -f third-party/entry-hub/config/server.dev-only.crt ] || third-party/entry-hub/generate-dev-cert.sh

export RAM_USB_CA_BOOTSTRAP_TOKEN=$(docker exec certificate-authority step ca token EntryHub \
  --ca-url https://certificate-authority:9000 --root /home/step/certs/root_ca.crt \
  --provisioner admin --password-file /run/secrets/ca-password.dev-only 2>/dev/null)

docker compose -f deployments/compose/entry-hub.yml up --build
