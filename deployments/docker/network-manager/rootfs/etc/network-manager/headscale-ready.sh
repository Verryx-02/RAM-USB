#!/bin/sh
# Blocks the network-manager longrun (dependencies.d/headscale-ready) from
# starting until Headscale's gRPC admin API is actually accepting
# connections, not merely that s6-rc has started the headscale longrun's
# process (same distinction pkg/mesh's memory notes make about not gating
# on shallow "started" state) - services/network-manager/cmd/network-manager/
# main.go's run() calls PushPolicy/CreateMeshUser against that API at
# startup and has no retry of its own for "connection refused".
#
# s6-rc oneshot up/down files are always parsed as execline, not a shell
# (a #! shebang line is silently treated as a comment) - this oneshot's own
# up file hands off to this real shell script instead of embedding the loop
# directly. No with-contenv needed: "headscale health" needs no env vars,
# it just dials Headscale's own gRPC listener (now 127.0.0.1:50443 per
# third-party/network-manager/headscale/config/config.yaml) directly.
set -eu

i=0
while ! /usr/local/bin/headscale health >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "headscale-ready: timed out waiting for headscale health" >&2
		exit 1
	fi
	sleep 1
done
