#!/bin/sh
# Blocks the nginx longrun (dependencies.d/headscale-ready) from starting
# until Headscale's own /health endpoint is actually accepting connections
# on loopback, not merely that s6-rc has started the headscale longrun's
# process (dependencies.d only guarantees "started", not "ready" - same
# distinction this project's other services' own readiness oneshots make,
# e.g. Storage-Service's/Network-Manager's former headscale-ready.sh).
# Without this, nginx would start proxying immediately and return 502s to
# every request (coordination traffic and /api/v1/* alike) during the
# brief window before Headscale finishes its own startup.
#
# s6-rc oneshot up/down files are always parsed as execline, not a shell
# (a #! shebang line is silently treated as a comment) - this oneshot's
# own up file hands off to this real shell script instead of embedding the
# loop directly.
set -eu

i=0
while ! curl -fsS http://127.0.0.1:8081/health >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "headscale-ready: timed out waiting for headscale /health" >&2
		exit 1
	fi
	sleep 1
done
