#!/bin/sh
# Runs once, automatically, via the official timescale/timescaledb image's
# own /docker-entrypoint-initdb.d/ convention (same mechanism init.sql's
# own doc comment documents) - AFTER initdb has already written its
# default pg_hba.conf, which is exactly why this can safely OVERWRITE that
# file rather than needing to reason about first-boot-vs-later-boot
# ordering: this script only ever runs on a fresh, empty data directory
# (KI-22, RNF-SEC-04).
#
# The upstream image's own docker-entrypoint.sh unconditionally appends
# "host all all all $POSTGRES_HOST_AUTH_METHOD" (default scram-sha-256) to
# pg_hba.conf BEFORE running any /docker-entrypoint-initdb.d/ script -
# confirmed by reading that script this session. A `host` record matches
# BOTH plaintext and SSL connections, so leaving it in place would make it
# match (and accept) a plaintext, no-client-cert connection FIRST - Postgres
# pg_hba.conf is first-match-wins, so any stricter `hostssl` rule appended
# after it would be dead code. This script therefore REPLACES the whole
# file instead of appending to it.
#
# hostssl ... clientcert=verify-full REQUIRES the client certificate's
# CommonName to exactly equal the role being connected as (no
# pg_ident.conf user-mapping layer added here - YAGNI, see this task's own
# report for the reasoning) - Grafana's own TimescaleDB client certificate
# is minted with subject "metrics_collector" for exactly this reason
# (deployments/compose/grafana.yml's own grafana-cert-issuer).
#
# scram-sha-256 (password) is kept ALONGSIDE clientcert=verify-full,
# rather than switching to auth-method "cert" and dropping the password -
# defense-in-depth per RNF-SEC-02/RNF-SEC-03 (every layer independently
# re-validates, not "the certificate alone is enough").
#
# "local" (Unix-domain-socket) connections stay `trust`: reachable only
# from a process inside this same container (pg_isready in
# timescaledb-ready.sh, this script's own psql invocations during initdb)
# - never network-reachable, so no credential is needed there.
#
# Metrics-Collector's OWN Go binary (services/metrics-collector/cmd/
# metrics-collector) connects over TCP to "localhost:5432" (pgxpool, MT-F-03)
# rather than the Unix socket above, and is EXEMPTED from the
# clientcert=verify-full requirement below via a loopback-scoped `host` rule
# still requiring the real POSTGRES_PASSWORD - deliberately, not a gap: that
# connection never leaves this container (RNF-SEC-04 governs
# INTER-service, cross-host/cross-container traffic; this is a service
# talking to its own co-located datastore, the same distinction that
# already leaves Database-Vault's own loopback-only Postgres with no mTLS
# requirement at all). Every OTHER caller - specifically Grafana,
# MT-F-04/UC-05's genuine cross-guest connection - is forced through the
# `hostssl ... clientcert=verify-full` rule.
cat > "$PGDATA/pg_hba.conf" <<EOF
local all all trust
host    ${POSTGRES_DB} ${POSTGRES_USER} 127.0.0.1/32 scram-sha-256
host    ${POSTGRES_DB} ${POSTGRES_USER} ::1/128      scram-sha-256
hostssl ${POSTGRES_DB} ${POSTGRES_USER} all          scram-sha-256 clientcert=verify-full
EOF
