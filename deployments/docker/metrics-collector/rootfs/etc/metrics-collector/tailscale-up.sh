#!/bin/sh
# Joins this container's real tailscaled (dependencies.d/tailscaled) to the
# Headscale mesh ONCE at container start (not per-connection) and stays
# joined for the container's whole lifetime - tailscaled itself is the
# long-lived process; this script (invoked by the tailscale-up oneshot's
# own "up" file, an execline script - s6-rc always parses oneshot up/down
# files as execline regardless of any shebang, so the actual shell logic
# below has to live in this separate file instead, same convention as
# Database-Vault's own tailscale-up.sh) performs the one-time "tailscale
# up" handshake.
#
# Unlike Database-Vault's own tailscale-up.sh, nothing here needs to hand
# this node's mesh IPv4 address to a later longrun via s6-overlay's
# container-environment directory: TimescaleDB binds to every local
# interface unconditionally (see ../s6-overlay/s6-rc.d/timescaledb/run's
# own doc comment for why "*" is the right choice here, unlike
# Database-Vault's own single-mesh-IP-only Go listener), and
# Metrics-Collector's own Go binary has no inbound listener of any kind
# to bind to a specific address either (see cmd/metrics-collector/
# main.go's own package doc comment) - so nothing in this container
# actually needs to know its own mesh IP at startup, only that the mesh
# join itself has completed.
#
# with-contenv (see the up file, not this file's own shebang, which is
# never invoked by the kernel): this is the one oneshot that needs
# RAM_USB_TAILSCALE_CONTROL_URL/RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY/
# RAM_USB_METRICS_COLLECTOR_MESH_HOSTNAME pushed back into its environment
# (S6_KEEP_ENV stays at its default 0).
set -eu

# Headscale's dev-only self-signed control-plane certificate, if present, is
# already trusted in the OS trust store by now: the trust-mesh-ca oneshot
# (see ../s6-overlay/s6-rc.d/trust-mesh-ca/) runs update-ca-certificates
# BEFORE tailscaled (a dependencies.d/tailscaled longrun dependency of
# trust-mesh-ca, not of this oneshot) is even started, since tailscaled
# reads and caches the OS certificate pool at its own process start.

# /var/run is a fresh tmpfs on every container start; tailscaled's own run
# script already recreates /var/run/tailscale itself, this is defensive
# only in case this oneshot ever runs before that longrun's first attempt.
mkdir -p -m 0755 /var/run/tailscale

# Waits for tailscaled's control socket - dependencies.d/tailscaled only
# guarantees the longrun has been STARTED by s6-rc, not that tailscaled has
# finished initializing its socket yet.
i=0
while [ ! -S /var/run/tailscale/tailscaled.sock ]; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "tailscale-up: timed out waiting for /var/run/tailscale/tailscaled.sock" >&2
		exit 1
	fi
	sleep 1
done

tailscale up \
	--login-server="${RAM_USB_TAILSCALE_CONTROL_URL:?RAM_USB_TAILSCALE_CONTROL_URL is not set}" \
	--authkey="${RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY:?RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY is not set}" \
	--hostname="${RAM_USB_METRICS_COLLECTOR_MESH_HOSTNAME:-metrics-collector}" \
	--reset

# Metrics-Collector's own outbound calls (Certificate-Authority, the MQTT
# broker) resolve their peers via the container's normal OS resolver, which
# only works if this node accepts the DNS configuration Headscale pushes -
# same reasoning as Database-Vault's own tailscale-up.sh, --accept-dns is
# deliberately left at its default (true), not disabled.
