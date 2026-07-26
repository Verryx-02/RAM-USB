#!/bin/sh
# mqtt-broker-ready oneshot (KI-28): polls TCP reachability of
# RAM_USB_MQTT_BROKER_URL's own host:port before the certificate-authority-
# metrics longrun starts. Unlike a same-container dependency (step-ca-
# ready above), this is a genuinely cross-container readiness question:
# certificate-authority-mesh (this container's own real tailscaled
# sidecar, deployments/compose/certificate-authority.yml) only starts
# AFTER this container reports healthy, and the MQTT broker itself is a
# separate Compose project entirely - so at this container's own start,
# neither the mesh route nor the broker is guaranteed up yet. Gating on
# this oneshot, rather than letting the metrics longrun crash-loop until
# both come up, matters here specifically because a crash AFTER a
# successful CA-bootstrap-token exchange can never retry that exchange
# (the token is single-use, see ../mint-metrics-token/mint-metrics-
# token.sh's own doc comment and docs/Known_Issues.md's "crash loop burns a
# single-use CA token" known issue) - so the metrics longrun must not even
# attempt to start until the broker is genuinely reachable.
#
# "nc -z" only proves TCP reachability, not a successful mTLS handshake
# (mosquitto still requires a valid client certificate on the real
# connection, PKI-F-02/NET-F-02, unaffected by this check) - sufficient to
# prove the broker/mesh route both exist, which is this oneshot's only
# job.
set -eu

BROKER_URL="${RAM_USB_MQTT_BROKER_URL:?RAM_USB_MQTT_BROKER_URL is not set}"
# Strip a "tls://" (or any "scheme://") prefix, then split host:port.
HOSTPORT="${BROKER_URL#*://}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"

i=0
while ! nc -z -w 2 "${HOST}" "${PORT}" >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 60 ]; then
		echo "mqtt-broker-ready: timed out waiting for ${HOST}:${PORT} to accept connections" >&2
		exit 1
	fi
	sleep 2
done
