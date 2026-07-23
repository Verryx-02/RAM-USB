#!/bin/sh
# Joins this container's real tailscaled (dependencies.d/tailscaled) to the
# Headscale mesh ONCE at container start (not per-connection) and stays
# joined for the container's whole lifetime - tailscaled itself is the
# long-lived process; this script (invoked by the tailscale-up oneshot's
# own "up" file, an execline script - s6-rc always parses oneshot up/down
# files as execline regardless of any shebang, so the actual shell logic
# below has to live in this separate file instead: "with-contenv
# /bin/sh /etc/network-manager/tailscale-up.sh" is what that up file
# execs) performs the one-time "tailscale up" handshake plus the runtime
# configuration steps that can only happen once this node's mesh IPv4
# address is known. network-manager (the Go binary, dependencies.d/
# tailscale-up) waits for this to finish before starting, since it binds
# exclusively to that address (NET-F-01). Identical shape to Storage-
# Service's own tailscale-up.sh, with two differences specific to this
# container: the login-server target below (Headscale is CO-LOCATED in
# this same container, not reached over ramusb-net) and --accept-dns=false
# (NM-F-16).
#
# with-contenv (see the up file, not this file's own shebang, which is
# never invoked by the kernel): this is the one oneshot that needs
# RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY/RAM_USB_NETWORK_MANAGER_MESH_HOSTNAME
# pushed back into its environment (S6_KEEP_ENV stays at its default 0,
# same convention as the network-manager longrun's own run script).
set -eu

# Headscale's dev-only self-signed control-plane certificate, if present, is
# already trusted in the OS trust store by now: the trust-mesh-ca oneshot
# (see ../s6-overlay/s6-rc.d/trust-mesh-ca/) runs update-ca-certificates
# BEFORE tailscaled (a dependencies.d/trust-mesh-ca longrun dependency, not
# of this oneshot) is even started, since tailscaled reads and caches the
# OS certificate pool at its own process start - doing it here instead
# would be too late for tailscaled's already-cached pool to ever see it.

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

# Headscale is co-located inside this SAME container (NM-F-14) - this
# node's own mesh join talks to it over loopback, not the ramusb-net
# hostname ("network-manager") every OTHER service's own mesh join uses to
# reach this container's Headscale (see deployments/compose/
# network-manager.yml's RAM_USB_TAILSCALE_CONTROL_URL, a DIFFERENT value
# for those other services). Hardcoded, not read from
# RAM_USB_TAILSCALE_CONTROL_URL: that env var's value
# (https://network-manager:8080, dialed by every OTHER service) would not
# even resolve correctly from inside this container for this purpose.
#
# --accept-dns=false (NM-F-16): this node must not accept the DNS
# configuration Headscale pushes to mesh members, to avoid a circular
# reference in its own host's DNS resolution (Headscale's MagicDNS
# nameserver answers are themselves served by this same co-located
# container) - unlike Storage-Service's node, which has no such circular
# dependency and leaves --accept-dns at its default.
tailscale up \
	--login-server="https://localhost:8080" \
	--authkey="${RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY:?RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY is not set}" \
	--hostname="${RAM_USB_NETWORK_MANAGER_MESH_HOSTNAME:-network-manager}" \
	--accept-dns=false \
	--reset

TS_IP="$(tailscale ip -4)"
if [ -z "$TS_IP" ]; then
	echo "tailscale-up: tailscale ip -4 returned no address" >&2
	exit 1
fi

# Hands this node's mesh IPv4 address to the longrun that starts after this
# oneshot (network-manager) via s6-overlay's container environment
# directory - with-contenv (used by its run script) re-reads this
# directory fresh on every process start, so a file written here after
# container init is picked up exactly like a docker-compose-supplied
# variable would be. Same pattern as Storage-Service's own tailscale-up.sh.
mkdir -p /var/run/s6/container_environment
printf '%s' "$TS_IP" >/var/run/s6/container_environment/RAM_USB_NETWORK_MANAGER_TAILSCALE_IP
