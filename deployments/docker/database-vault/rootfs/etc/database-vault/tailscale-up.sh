#!/bin/sh
# Joins this container's real tailscaled (dependencies.d/tailscaled) to the
# Headscale mesh ONCE at container start (not per-connection) and stays
# joined for the container's whole lifetime - tailscaled itself is the
# long-lived process; this script (invoked by the tailscale-up oneshot's
# own "up" file, an execline script - s6-rc always parses oneshot up/down
# files as execline regardless of any shebang, so the actual shell logic
# below has to live in this separate file instead: "with-contenv
# /bin/sh /etc/database-vault/tailscale-up.sh" is what that up file execs,
# per with-contenv's own "with-contenv prog args..." contract) performs the
# one-time "tailscale up" handshake plus the runtime configuration steps
# that can only happen once this node's mesh IPv4 address is known. The
# database-vault longrun (dependencies.d/tailscale-up) waits for this to
# finish before starting, since it binds its register/login listener
# exclusively to that address (NET-F-01). Reaches an EXTERNAL Headscale
# over ramusb-net at join time - unlike Network-Manager's own co-located
# conversion, Database-Vault has no local shortcut to it, exactly like
# Storage-Service's own tailscale-up.sh, which this file mirrors closely.
#
# with-contenv (see the up file, not this file's own shebang, which is
# never invoked by the kernel): this is the one oneshot that needs
# RAM_USB_TAILSCALE_CONTROL_URL/RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY/
# RAM_USB_DATABASE_VAULT_MESH_HOSTNAME pushed back into its environment
# (S6_KEEP_ENV stays at its default 0, same convention documented in
# ../s6-overlay/s6-rc.d/database-vault/run for the database-vault longrun).
set -eu

# Headscale's dev-only self-signed control-plane certificate, if present, is
# already trusted in the OS trust store by now: the trust-mesh-ca oneshot
# (see ../s6-overlay/s6-rc.d/trust-mesh-ca/) runs update-ca-certificates
# BEFORE tailscaled (a dependencies.d/tailscaled longrun dependency of
# trust-mesh-ca, not of this oneshot) is even started, since tailscaled
# reads and caches the OS certificate pool at its own process start - doing
# it here instead, after dependencies.d/tailscaled already guarantees
# tailscaled has been started, updates the on-disk trust store too late for
# tailscaled's already-cached pool to ever see it.

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
	--authkey="${RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY:?RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY is not set}" \
	--hostname="${RAM_USB_DATABASE_VAULT_MESH_HOSTNAME:-database-vault}" \
	--reset

# Database-Vault's own outbound calls (Storage-Service, the Certificate-
# Authority, the MQTT broker) resolve their peers via the container's
# normal OS resolver, which only works if this node accepts the DNS
# configuration Headscale pushes - unlike Network-Manager's own node
# (NM-F-16), Database-Vault's node has no circular-reference reason to
# refuse it, so --accept-dns is deliberately left at its default (true),
# not disabled.

TS_IP="$(tailscale ip -4)"
if [ -z "$TS_IP" ]; then
	echo "tailscale-up: tailscale ip -4 returned no address" >&2
	exit 1
fi

# Hands this node's mesh IPv4 address to the longrun that starts after this
# oneshot (database-vault) via s6-overlay's container environment
# directory - with-contenv (used by that longrun, see its own run script)
# re-reads this directory fresh on every process start, so a file written
# here after container init is picked up exactly like a docker-compose-
# supplied variable would be.
mkdir -p /var/run/s6/container_environment
printf '%s' "$TS_IP" >/var/run/s6/container_environment/RAM_USB_DATABASE_VAULT_TAILSCALE_IP
