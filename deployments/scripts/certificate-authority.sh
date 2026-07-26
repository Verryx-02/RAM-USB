#!/bin/bash
# Shell 1 - Certificate-Authority + its Tailscale mesh sidecar (NM-F-04) +
# CA-F-03's metrics sidecar. Runs first, standalone - the CA server itself
# needs nothing else up yet (shell 2, headscale.sh, needs THIS shell's root
# certificate). Only this script's own mesh SIDECAR (certificate-authority-
# mesh) needs Headscale reachable, and Headscale does not exist yet at this
# point in the manual procedure - that sidecar will retry for ~30-40s and
# then exit (a known, accepted quirk of the Tailscale sidecar pattern this
# project already documents - see MANUAL-DISTRIBUTED-RUN.md's own Known
# Issues). Simply re-run this script once shell 2 (Headscale) is up; it is
# safe to re-run (network/user-creation steps no-op if already done).
#
# CA-F-03's own metrics sidecar (docs/Known_Issues.md's KI-28) is no
# longer a separate compose project/script: it is s6-supervised inside
# this SAME container/image (deployments/docker/certificate-authority/),
# and mints its own CA-F-04 bootstrap token locally once step-ca itself is
# healthy (see that Dockerfile/rootfs's own mint-metrics-token oneshot) -
# no separate `docker exec`/manual minting step, and no separate Tailscale
# identity, needed for it anymore. Its own MQTT publish only succeeds once
# the mesh sidecar below AND the MQTT broker (shell 4) are both reachable -
# see this container's own mqtt-broker-ready oneshot.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

docker network create ramusb-net 2>/dev/null || true

docker exec headscale headscale users create certificate-authority 2>/dev/null || true
CA_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="certificate-authority") | .id')
export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"
export RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$CA_ID" --expiration 30m --tags tag:certificate-authority)

docker compose -f deployments/compose/certificate-authority.yml up --build
