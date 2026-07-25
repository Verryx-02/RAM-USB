#!/bin/sh
# timescaledb-ready oneshot: polls the same readiness command Database-
# Vault's own postgres-ready.sh uses. dependencies.d/timescaledb only
# guarantees s6-rc has STARTED the timescaledb longrun, not that
# TimescaleDB has finished initdb (plus the timescaledb extension's own
# CREATE EXTENSION, see third-party/timescaledb/init.sql) and is accepting
# connections yet. The metrics-collector longrun depends on this oneshot
# finishing successfully before it starts, so its first connection attempt
# never races TimescaleDB's own startup/initdb window.
set -eu

i=0
while ! pg_isready -U metrics_collector -d metrics_collector >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		echo "timescaledb-ready: timed out waiting for TimescaleDB to accept connections" >&2
		exit 1
	fi
	sleep 1
done
