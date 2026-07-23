#!/bin/sh
# Trusts Headscale's dev-only self-signed control-plane certificate in this
# container's OS-level trust store BEFORE the tailscaled longrun (see
# ../s6-overlay/s6-rc.d/tailscaled/, which depends on this oneshot via
# dependencies.d/trust-mesh-ca) ever starts.
#
# Ordering is the whole point of this oneshot's existence: tailscaled reads
# and caches the OS certificate pool (crypto/x509.SystemCertPool()) at ITS
# OWN process start. Running update-ca-certificates after tailscaled has
# already started updates the on-disk trust store but never reaches
# tailscaled's already-cached in-memory pool, so every control-plane dial
# keeps failing closed with "certificate signed by unknown authority" for
# the container's entire lifetime. Splitting the update-ca-certificates
# step into this separate, earlier oneshot - a LONGRUN dependency, not a
# same-oneshot ordering trick - is the only fix: tailscaled must never
# observe a stale cert pool on its very first read. Identical reasoning and
# shape to Storage-Service's own trust-mesh-ca.sh.
#
# This container is co-located with the Headscale coordination server this
# node's own tailscale-up joins (localhost:8080) - the certificate trusted
# here is the SAME dev-only self-signed certificate Headscale itself serves
# (third-party/network-manager/headscale/dev-tls), mounted a second time at
# this fixed path by deployments/compose/network-manager.yml so the OS
# trust-store mechanism applies to it exactly like Storage-Service's own
# (external) Headscale certificate.
set -eu

if [ -f /usr/local/share/ca-certificates/headscale-dev.crt ]; then
	update-ca-certificates
fi
