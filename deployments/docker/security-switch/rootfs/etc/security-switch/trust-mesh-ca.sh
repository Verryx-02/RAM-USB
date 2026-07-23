#!/bin/sh
# Trusts Headscale's dev-only self-signed control-plane certificate in this
# container's OS-level trust store BEFORE the tailscaled longrun (see
# ../s6-overlay/s6-rc.d/tailscaled/, which depends on this oneshot via
# dependencies.d/trust-mesh-ca) ever starts.
#
# Ordering is the whole point of this oneshot's existence: tailscaled reads
# and caches the OS certificate pool (crypto/x509.SystemCertPool()) at ITS
# OWN process start. Running update-ca-certificates AFTER tailscaled has
# already started updates the on-disk trust store but never reaches
# tailscaled's already-cached in-memory pool, so every control-plane dial
# keeps failing closed with "certificate signed by unknown authority" for
# the container's entire lifetime - same finding already confirmed live for
# Storage-Service's identical oneshot (see
# deployments/docker/storage-service/rootfs/etc/storage-service/
# trust-mesh-ca.sh for the full incident description). Splitting the
# update-ca-certificates step into this separate, earlier oneshot - a
# LONGRUN dependency, not a same-oneshot ordering trick - is the only fix.
#
# This base image has a real shell and ca-certificates package, so the
# standard OS trust-store mechanism applies directly here, unlike pkg/mesh's
# distroless SSL_CERT_FILE workaround this container no longer uses.
#
# Headscale's dev-only self-signed control-plane certificate (mounted read-
# only at this fixed path by deployments/compose/security-switch.yml, same
# file already trusted the same way by Storage-Service and the
# tailscale-test.yml reference container). Left absent in a real deployment
# once RAM_USB_TAILSCALE_CONTROL_URL carries a publicly-trusted-root
# certificate - in that case this oneshot is a no-op, and completes
# successfully either way (no cert file is not an error here).
set -eu

if [ -f /usr/local/share/ca-certificates/headscale-dev.crt ]; then
	update-ca-certificates
fi
