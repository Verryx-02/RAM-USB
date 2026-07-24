#!/bin/bash
# Shell 1 - Certificate-Authority + its Tailscale mesh sidecar (NM-F-04).
# Runs first, standalone - the CA server itself needs nothing else up yet
# (shell 2, headscale.sh, needs THIS shell's root certificate). Only this
# script's own mesh SIDECAR (certificate-authority-mesh) needs Headscale
# reachable, and Headscale does not exist yet at this point in the manual
# procedure - that sidecar will retry for ~30-40s and then exit (a known,
# accepted quirk of the Tailscale sidecar pattern this project already
# documents - see MANUAL-DISTRIBUTED-RUN.md's own Known Issues). Simply
# re-run this script once shell 2 (Headscale) is up; it is safe to re-run
# (network/user-creation steps no-op if already done).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec headscale headscale users create certificate-authority 2>/dev/null || true
CA_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="certificate-authority") | .id')
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$CA_ID" --expiration 30m --tags tag:certificate-authority)

docker compose -f deployments/compose/certificate-authority.yml up
