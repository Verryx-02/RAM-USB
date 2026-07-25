#!/bin/sh
# Trusts Headscale's dev-only self-signed control-plane certificate in this
# container's OS-level trust store BEFORE the tailscaled longrun (see
# ../s6-overlay/s6-rc.d/tailscaled/, which depends on this oneshot via
# dependencies.d/trust-mesh-ca) ever starts. Ordering is the whole point of
# this oneshot's existence - identical reasoning to Database-Vault's own
# trust-mesh-ca.sh (see that file's own doc comment for the full
# "tailscaled caches the OS cert pool at its own process start" finding).
#
# This base image (timescale/timescaledb, Debian-based) has a real shell
# and ca-certificates package, so the standard OS trust-store mechanism
# applies directly here.
#
# Headscale's dev-only self-signed control-plane certificate (mounted read-
# only at this fixed path by deployments/compose/metrics-collector.yml,
# same file already trusted the same way by Database-Vault/Storage-Service/
# Mosquitto). Left absent in a real deployment once
# RAM_USB_TAILSCALE_CONTROL_URL carries a publicly-trusted-root certificate
# - in that case this oneshot is a no-op, and completes successfully either
# way (no cert file is not an error here).
set -eu

if [ -f /usr/local/share/ca-certificates/headscale-dev.crt ]; then
	update-ca-certificates
fi
