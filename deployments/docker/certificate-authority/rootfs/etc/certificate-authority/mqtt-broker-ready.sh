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
# The probe only proves TCP reachability, not a successful mTLS handshake
# (mosquitto still requires a valid client certificate on the real
# connection, PKI-F-02/NET-F-02, unaffected by this check) - sufficient to
# prove the broker/mesh route both exist, which is this oneshot's only job.
#
# KI-60, no deadline: this loop deliberately has no timeout. A failed s6-rc
# oneshot is TERMINAL for the whole container's lifetime - every dependent
# (here: certificate-authority-metrics) stays down until the container is
# recreated, with no retry and no signal. MANUAL-DISTRIBUTED-RUN.md starts
# the MQTT broker three shells AFTER this one, so any operator slower than
# the old two-minute budget got a healthy CA that would never publish a
# single metric again (CA-F-03). Exiting 0 on a deadline instead is NOT an
# option here: the metrics longrun consumes its single-use CA-F-04
# bootstrap token (services/certificate-authority/cmd/metrics-sidecar/
# main.go's buildMQTTIdentity) BEFORE it dials the broker, so starting it
# early would burn the token and leave every later respawn permanently
# unable to bootstrap - trading a delayed metric for a dead one. Blocking
# here costs nothing: step-ca itself has no dependency on this oneshot, and
# the branch resumes on its own the moment the broker appears.
#
# The probe uses curl, not "nc -z": this image is Alpine-based
# (smallstep/step-ca), where nc is the BusyBox applet whose -z flag is not
# guaranteed to be compiled in, and the Dockerfile installs only xz on top
# of the base. curl is confirmed present in that base image (see the
# Dockerfile's own apk comment) and has documented, stable exit codes: 6
# (host not resolvable, i.e. MagicDNS not up yet), 7 (connection refused /
# not reachable) and 28 (timed out before connecting) all mean "not ready".
# Any other code - notably 35/60, a TLS error - means the TCP connection
# was established, which is exactly what this oneshot tests for.
set -eu

BROKER_URL="${RAM_USB_MQTT_BROKER_URL:?RAM_USB_MQTT_BROKER_URL is not set}"
# Strip a "tls://" (or any "scheme://") prefix, then split host:port.
HOSTPORT="${BROKER_URL#*://}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"

i=0
while true; do
	rc=0
	curl --silent --connect-timeout 2 --max-time 5 --insecure \
		"https://${HOST}:${PORT}" >/dev/null 2>&1 || rc=$?
	case "$rc" in
	6 | 7 | 28) ;;
	*) break ;;
	esac

	i=$((i + 1))
	# One line a minute, not one every two seconds: enough for an operator
	# to see this is the branch still waiting, without flooding the log for
	# however long it takes them to reach the MQTT-broker shell.
	if [ $((i % 30)) -eq 0 ]; then
		echo "mqtt-broker-ready: still waiting for ${HOST}:${PORT} (start the MQTT broker to let CA-F-03 metrics begin)" >&2
	fi
	sleep 2
done
