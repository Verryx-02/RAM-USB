#!/bin/sh
# postgres-ready oneshot: polls the SAME command
# deployments/compose/database-vault.yml's Postgres service previously used
# as a Compose-level healthcheck (before Postgres was merged into this
# container). dependencies.d/postgres only guarantees s6-rc has STARTED the
# postgres longrun, not that Postgres has finished initdb and is accepting
# connections yet - the same "started" vs "ready" distinction already
# documented in Storage-Service's tailscale-up.sh. The database-vault
# longrun depends on this oneshot finishing successfully before it starts
# (dependencies.d/postgres-ready), so its first connection attempt never
# races Postgres's own startup/initdb window.
set -eu

i=0
while ! pg_isready -U database_vault -d database_vault >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "postgres-ready: timed out waiting for Postgres to accept connections" >&2
		exit 1
	fi
	sleep 1
done
