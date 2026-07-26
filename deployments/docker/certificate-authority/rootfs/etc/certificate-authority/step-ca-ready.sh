#!/bin/sh
# step-ca-ready oneshot: polls the SAME health command deployments/compose/
# certificate-authority.yml's own Compose-level healthcheck uses.
# dependencies.d/step-ca only guarantees s6-rc has STARTED the step-ca
# longrun, not that step-ca has finished loading its config/keys and is
# actually serving HTTPS yet - the same "started" vs "ready" distinction
# Database-Vault's own postgres-ready.sh documents. mint-metrics-token
# (../mint-metrics-token/) depends on this oneshot finishing successfully
# before it runs, so its own local "step ca token" call never races
# step-ca's own startup window.
set -eu

i=0
while ! step ca health --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "step-ca-ready: timed out waiting for step-ca to accept connections" >&2
		exit 1
	fi
	sleep 1
done
