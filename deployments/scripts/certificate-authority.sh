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

export RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080"

# KI-58: on a clean machine the `headscale` container does not exist yet -
# this script runs BEFORE shell 2 by design (see the header comment). The
# pre-auth-key minting below is therefore conditional: without the guard,
# `docker exec headscale ...` exits 1, `pipefail` propagates it through the
# `jq` pipe, and `set -e` kills this script before the `docker compose up`
# below ever runs - leaving headscale.sh's own readiness loop waiting
# forever on a CA that was never started.
#
# certificate-authority.yml requires RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY
# as `${VAR:?...}` (fail-secure, RD-04), so it cannot simply be left unset:
# Compose refuses to interpolate the file at all and nothing starts. A
# clearly-labelled placeholder is used instead - the mesh sidecar then fails
# to authenticate and exits, which is the SAME observable outcome this
# script's header already documents for "Headscale is not up yet", while
# step-ca itself starts normally and shell 2 can fetch its root certificate.
if docker inspect headscale >/dev/null 2>&1; then
	docker exec headscale headscale users create certificate-authority 2>/dev/null || true
	CA_ID=$(docker exec headscale headscale users list -o json | jq -r '.[] | select(.name=="certificate-authority") | .id')
	export RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY=$(docker exec headscale headscale preauthkeys create --user "$CA_ID" --expiration 30m --tags tag:certificate-authority)
else
	echo "certificate-authority.sh: no 'headscale' container yet - starting step-ca WITHOUT a mesh identity." >&2
	echo "certificate-authority.sh: re-run this script after shell 2 (headscale.sh) is up to join the mesh (NM-F-04)." >&2
	export RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY="placeholder-no-headscale-yet-rerun-this-script"
fi

docker compose -f deployments/compose/certificate-authority.yml up --build
