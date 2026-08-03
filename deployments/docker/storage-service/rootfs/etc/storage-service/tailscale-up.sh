#!/bin/sh
# Joins this container's real tailscaled (dependencies.d/tailscaled) to the
# Headscale mesh ONCE at container start (not per-connection) and stays
# joined for the container's whole lifetime - tailscaled itself is the
# long-lived process; this script (invoked by the tailscale-up oneshot's
# own "up" file, an execline script - s6-rc always parses oneshot up/down
# files as execline regardless of any shebang, so the actual shell logic
# below has to live in this separate file instead: "with-contenv
# /bin/sh /etc/storage-service/tailscale-up.sh" is what that up file
# execs, per with-contenv's own "with-contenv prog args..." contract)
# performs the one-time "tailscale up" handshake plus the runtime
# configuration steps that can only happen once this node's mesh IPv4
# address is known. sshd and storage-service (dependencies.d/tailscale-up
# on each) both wait for this to finish before starting, since both bind
# exclusively to that address (NET-F-01).
#
# with-contenv (see the up file, not this file's own shebang, which is
# never invoked by the kernel): this is the one oneshot that needs
# RAM_USB_TAILSCALE_CONTROL_URL/RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY/
# RAM_USB_STORAGE_SERVICE_MESH_HOSTNAME pushed back into its environment
# (S6_KEEP_ENV stays at its default 0, same convention already documented
# in ../s6-overlay/s6-rc.d/storage-service/run for the storage-service
# longrun).
set -eu

# Headscale's dev-only self-signed control-plane certificate, if present, is
# already trusted in the OS trust store by now: the trust-mesh-ca oneshot
# (see ../s6-overlay/s6-rc.d/trust-mesh-ca/) runs update-ca-certificates
# BEFORE tailscaled (a dependencies.d/tailscaled longrun dependency of
# trust-mesh-ca, not of this oneshot) is even started, since tailscaled
# reads and caches the OS certificate pool at its own process start - doing
# it here instead, after dependencies.d/tailscaled already guarantees
# tailscaled has been started, updates the on-disk trust store too late for
# tailscaled's already-cached pool to ever see it (confirmed live: an
# indefinite "certificate signed by unknown authority" doLogin retry loop,
# node stuck "offline" for the container's whole lifetime).

# /var/run is a fresh tmpfs on every container start; tailscaled's own run
# script already recreates /var/run/tailscale itself, this is defensive
# only in case this oneshot ever runs before that longrun's first attempt.
mkdir -p -m 0755 /var/run/tailscale

# Waits for tailscaled's control socket - dependencies.d/tailscaled only
# guarantees the longrun has been STARTED by s6-rc, not that tailscaled has
# finished initializing its socket yet (same distinction already noted in
# pkg/mesh's memory notes about not gating on shallow "up" state).
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
	--authkey="${RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY:?RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY is not set}" \
	--hostname="${RAM_USB_STORAGE_SERVICE_MESH_HOSTNAME:-storage-service}" \
	--reset

# ST-F-11's AuthorizedKeysCommand resolves Database-Vault's MagicDNS short
# hostname via the container's normal OS resolver (net/http's default
# dialer), which only works if this node accepts the DNS configuration
# Headscale pushes - unlike Network-Manager's own node (NM-F-16), Storage-
# Service's node has no circular-reference reason to refuse it, so
# --accept-dns is deliberately left at its default (true), not disabled.

TS_IP="$(tailscale ip -4)"
if [ -z "$TS_IP" ]; then
	echo "tailscale-up: tailscale ip -4 returned no address" >&2
	exit 1
fi

# Hands this node's mesh IPv4 address to the two longruns that start after
# this oneshot (sshd, storage-service) via s6-overlay's container
# environment directory - with-contenv (used by both, see their own run
# scripts) re-reads this directory fresh on every process start, so a file
# written here after container init is picked up exactly like a
# docker-compose-supplied variable would be.
mkdir -p /var/run/s6/container_environment
printf '%s' "$TS_IP" >/var/run/s6/container_environment/RAM_USB_STORAGE_SERVICE_TAILSCALE_IP

# sshd_config(5) has no runtime templating of its own, and this node's mesh
# IPv4 address is only known now, at container start, not at image build
# time - append a global ListenAddress directive restricting sshd to this
# one interface (NET-F-01), before its "Match User user*" block (a
# ListenAddress after a Match block would not be a syntax error but would
# not be a top-level/global directive either - sshd_config(5) scopes every
# directive after a Match line to that Match, so this insertion point,
# right after the existing top-level "Port 2222" line, is the only correct
# one). Idempotent: harmless if this oneshot ever ran more than once
# against the same sshd_config copy.
if ! grep -q "^ListenAddress ${TS_IP}\$" /etc/ssh/sshd_config; then
	sed -i "/^Port 2222\$/a ListenAddress ${TS_IP}" /etc/ssh/sshd_config
fi

# Post-condition, not decoration: sed exits 0 whether or not its address
# matched, and "set -e" cannot see a no-op. If the "Port 2222" line in
# sshd_config is ever reworded, commented or re-indented, the insertion
# above would silently do nothing and sshd would start with no
# ListenAddress at all - listening on 0.0.0.0:2222, the exact NET-F-01
# violation this insertion exists to prevent. Failing the oneshot here
# keeps sshd (dependencies.d/tailscale-up) from ever starting in that
# state (RD-04).
if ! grep -q "^ListenAddress ${TS_IP}\$" /etc/ssh/sshd_config; then
	echo "tailscale-up: failed to pin ListenAddress ${TS_IP} in /etc/ssh/sshd_config" >&2
	exit 1
fi
