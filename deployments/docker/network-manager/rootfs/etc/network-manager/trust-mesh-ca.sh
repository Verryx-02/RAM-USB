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
# Headscale is a separately-deployed container this session (see
# cmd/network-manager/main.go's own package doc comment for why) - this
# node's own tailscale-up dials it like every other mesh-joined service
# does, over RAM_USB_TAILSCALE_CONTROL_URL. The certificate trusted here is
# the SAME dev-only self-signed certificate that separate Headscale
# deployment's reverse proxy serves (third-party/headscale/dev-tls),
# mounted here by deployments/compose/network-manager.yml so the OS
# trust-store mechanism applies to it exactly like Storage-Service's own
# (also external) Headscale certificate trust.
set -eu

if [ -f /usr/local/share/ca-certificates/headscale-dev.crt ]; then
	update-ca-certificates
fi
