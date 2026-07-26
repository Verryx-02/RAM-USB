# Metrics-Collector: Proxmox deployment notes

TimescaleDB (MT-F-03) is co-located inside this same container/guest
(`deployments/docker/metrics-collector/Dockerfile`), the same "absorb the
third-party server into one image" pattern already used for Database-Vault
+Postgres and Network-Manager+Headscale - see `docs/Known_Issues.md`'s
KI-18 for the decision record. This file was originally written before
that decision existed (describing reaching TimescaleDB over "the private
network" as a separate dependency) - updated here to the real, now-decided
placement.

## What this process is

A single container with two supervised processes (s6-overlay): Metrics-
Collector's own Go binary - an mTLS MQTT subscribe connection (MT-F-01)
and a `localhost`-only Postgres/TimescaleDB write connection (MT-F-03),
no inbound network listener at all (see `main.go`'s own package doc
comment) - and TimescaleDB itself, which Grafana's own outbound query
connection (MT-F-04, UC-05) reaches directly, not through the Go binary.
No sshd, no POSIX user provisioning, no chroot: an unprivileged LXC
container is sufficient, the same category of workload as Network-Manager
(an outbound-heavy, no-OS-level-work Go process) plus Database-Vault's own
co-located-datastore precedent, not Storage-Service (which genuinely needs
real OS-level capabilities).

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1-2 vCPU, 512 MB-1 GB RAM: TimescaleDB's own footprint dominates this
  guest's sizing now (previously a separate dependency's own problem) -
  the Go binary itself still holds nothing in memory beyond one MQTT
  client's connection state and one pgx connection pool.
- Modest disk: the binary itself, its `migrations/` directory (applied
  once at startup), PLUS TimescaleDB's own persistent data volume (30-day
  retention, MT-F-03) - unlike before this session's merge, this guest now
  holds real persistent state, not none.

## Network placement (NET-F-01)

**Two different connections, two different rules:**

1. **Metrics-Collector's own Go binary -> MQTT broker/Certificate-
   Authority (outbound)**: reachable only from the private network/mesh
   this stack's other services already live on - no port needs to be
   exposed to anything outside that private network, since nothing calls
   Metrics-Collector's own process; it only calls out.
2. **Grafana -> TimescaleDB (outbound, UC-05's own "query on Grafana ->
   TimescaleDB")**: over the Tailscale mesh, same rule as every other
   cross-guest RAM-USB connection (NET-F-01, RNF-SEC-04) - confirmed
   directly with the user (`deployments/proxmox/grafana.md`'s own
   "Network placement" section). This is why this guest now also carries a
   real, OS-level `tailscaled` (not `pkg/mesh`'s in-process `tsnet`):
   TimescaleDB is a separate OS process from the Go binary and needs a
   genuine kernel network interface to bind to, which only a real
   `tailscaled` provides - see
   `deployments/docker/metrics-collector/Dockerfile`'s own package doc
   comment. TimescaleDB itself binds to every local interface (`-c
   listen_addresses=*`, see the `timescaledb` longrun's own `run` script)
   rather than Database-Vault's own Postgres's loopback-only restriction,
   precisely because it must be reachable from Grafana's separate guest -
   in production (no other network attached to this guest, no
   host-published port) that still means "loopback plus the mesh
   interface only," not a general network exposure.

No host-published TimescaleDB port either way (`ports:` is absent from
`deployments/compose/metrics-collector.yml`).

## TimescaleDB's own mTLS server identity (KI-22, RNF-SEC-04, PKI-F-03)

TimescaleDB's own `pg_hba.conf` (`third-party/timescaledb/pg_hba-mtls.sh`,
applied via the upstream image's `docker-entrypoint-initdb.d` convention)
requires `hostssl ... clientcert=verify-full` for every REMOTE
(non-loopback) connection - Grafana's own (`deployments/proxmox/
grafana.md`'s "mTLS to TimescaleDB"), the only one that exists today.
Metrics-Collector's OWN Go binary, connecting over TCP to
`localhost:5432` (MT-F-03), is exempted from the client-certificate
requirement via a loopback-scoped rule (still requiring the real
`POSTGRES_PASSWORD`) - a principled distinction, not a gap: that
connection never leaves this guest, the same reasoning that already
leaves Database-Vault's own loopback-only Postgres with no mTLS
requirement at all.

TimescaleDB's own server certificate (CommonName
`MetricsCollectorTimescaleDB`) is minted and kept renewed by
`metrics-collector-timescaledb-cert-issuer`/
`metrics-collector-timescaledb-cert-renewer`
(`deployments/compose/metrics-collector.yml`) - the same CA-F-04
bootstrap-token-then-mTLS-renewal lifecycle every pkg/pki-integrated Go
service gets, adapted for a co-located third-party process that cannot
call pkg/pki itself (same shape as Mosquitto's own KI-16 sidecars). The
renewer reloads the new certificate by signaling the real `postgres`
process directly (its PID read from the co-located data volume's own
`postmaster.pid`), sharing this container's PID namespace to make that
signal land on the real process rather than mqtt-broker-cert-renewer's
simpler `kill -HUP 1` (postgres is not this container's own PID 1;
s6-overlay's supervisor is).

## Dependencies that must exist first

- The MQTT broker (Mosquitto), reachable at the address
  `RAM_USB_MQTT_BROKER_URL` names, with this process's own dev-only or
  production client certificate/key already provisioned and its ACL grant
  (`third-party/mosquitto/acl.conf`: `user MetricsCollector` / `topic read
  metrics/#`) already in place.
- The Certificate-Authority (CA-F-04), reachable over the mesh, to
  bootstrap this process's own mTLS identity and this guest's own
  Tailscale pre-auth key exchange.
- The separately-deployed Headscale/reverse-proxy VPS (NM-F-14), reachable
  at `RAM_USB_TAILSCALE_CONTROL_URL` over the public internet, to mint
  this guest's own single-use Tailscale pre-auth key before the mesh join
  can happen.
- `third-party/timescaledb/init.sql`'s own `CREATE EXTENSION IF NOT EXISTS
  timescaledb` step, applied automatically by the upstream
  `timescale/timescaledb` image's own `docker-entrypoint-initdb.d`
  mechanism on first boot (see that file's own doc comment for why this
  step happens outside this process's own Go migrations).

## Environment variables (see `main.go`'s own `const` block, plus
`deployments/compose/metrics-collector.yml`, for the authoritative list
and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker.internal:8883` |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA-F-04 bootstrap token for this process's own mTLS identity |
| `RAM_USB_METRICS_COLLECTOR_DATABASE_URL` | yes | TimescaleDB/Postgres connection string - always `localhost`, TimescaleDB is co-located |
| `RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR` | no (defaults to the checked-in `services/metrics-collector/migrations` path) | Migration files directory |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | Consumed by the co-located TimescaleDB's own `docker-entrypoint.sh`, same value referenced by `RAM_USB_METRICS_COLLECTOR_DATABASE_URL` above |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | Headscale's real public VPS coordination URL |
| `RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key for this guest's own mesh join, tagged `tag:metrics-collector` (`services/network-manager/internal/headscale/policy.go`) |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure) - unlike every publish-side service, for which the same
`RAM_USB_MQTT_*` variables are optional, since MQTT is this process's
entire purpose, not a side effect of an otherwise-independent server.

## What a real (non-dev) deployment still needs, not yet decided here

- A production MQTT client certificate issuance/rotation path for this
  process (PKI-F-03 - "should" exist, not yet built for MQTT identities
  at all, dev or production; see `third-party/mosquitto/generate-dev-certs.sh`'s
  own doc comment for the current dev-only judgment call and why MQTT
  identities are deliberately outside `pkg/pki`'s CA-F-04 bootstrap flow).
- `ramusb-metrics-collector-timescaledb-data`'s durability guarantee at the
  real Proxmox guest level (a persistent disk/volume surviving guest
  restart, not just container restart) - same open item as every other
  component's Proxmox note; this guest now genuinely needs this, unlike
  before this session's merge.
- Log shipping/monitoring of this process's own health, beyond what
  `slog`'s stdout output provides - out of this task's scope (MT-F-01..04
  cover collecting *other* services' metrics, not observing
  Metrics-Collector itself).
