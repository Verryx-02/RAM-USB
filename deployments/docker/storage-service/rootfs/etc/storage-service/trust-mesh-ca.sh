#!/bin/sh
# Trusts Headscale's dev-only self-signed control-plane certificate in this
# container's OS-level trust store BEFORE the tailscaled longrun (see
# ../s6-overlay/s6-rc.d/tailscaled/, which depends on this oneshot via
# dependencies.d/trust-mesh-ca) ever starts.
#
# Ordering is the whole point of this oneshot's existence: tailscaled reads
# and caches the OS certificate pool (crypto/x509.SystemCertPool(), the same
# sync.Once-cached-on-first-handshake behavior already documented in
# pkg/mesh's memory notes for tsnet's identical control-plane dial) at ITS
# OWN process start. Running update-ca-certificates AFTER tailscaled has
# already started - which is what the old tailscale-up.sh oneshot did,
# since it only runs once dependencies.d/tailscaled guarantees tailscaled
# has been started by s6-rc - updates the on-disk trust store but never
# reaches tailscaled's already-cached in-memory pool, so every control-plane
# dial keeps failing closed with "certificate signed by unknown authority"
# for the container's entire lifetime (confirmed live: tailscaled retried
# doLogin every ~7-10s indefinitely, node stayed "offline" in
# "headscale nodes list", until the container was recreated). Splitting the
# update-ca-certificates step into this separate, earlier oneshot - a
# LONGRUN dependency, not a same-oneshot ordering trick - is the only fix:
# tailscaled must never observe a stale cert pool on its very first read.
#
# This base image has a real shell and ca-certificates package, so the
# standard OS trust-store mechanism applies directly here, unlike
# pkg/mesh's distroless SSL_CERT_FILE workaround (Security-Switch/
# Database-Vault), which exists only because those images have no shell to
# run update-ca-certificates at all.
#
# Headscale's dev-only self-signed control-plane certificate (mounted read-
# only at this fixed path by deployments/compose/storage-service.yml, same
# file already trusted the same way by third-party/mosquitto and the
# tailscale-test.yml reference container). Left absent in a real deployment
# once RAM_USB_TAILSCALE_CONTROL_URL carries a publicly-trusted-root
# certificate - in that case this oneshot is a no-op, and completes
# successfully either way (no cert file is not an error here).
set -eu

if [ -f /usr/local/share/ca-certificates/headscale-dev.crt ]; then
	update-ca-certificates
fi
