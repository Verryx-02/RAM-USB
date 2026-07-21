# Metrics-Collector: Proxmox deployment notes

Every other `deployments/proxmox/*.md` file in this repository is still an
empty placeholder as of this writing, so there is no established sibling
example to mirror here (unlike this task's other scaffolded files, which
had a real, filled-in counterpart elsewhere in the repo to follow). This
file is therefore written directly from
`services/metrics-collector/cmd/metrics-collector/main.go`'s own
requirements and `deployments/docker-compose.dev.yml`'s dev-stack wiring,
translated to a Proxmox LXC container instead of a Compose service - not
copied from a pattern established by another already-written proxmox note.

## What this process is

A single Go binary with no inbound network listener at all (see
`main.go`'s own package doc comment): it makes two outbound connections -
an mTLS MQTT subscribe connection to the broker (MT-F-01) and a Postgres/
TimescaleDB write connection (MT-F-03) - and otherwise sits idle between
messages. No sshd, no POSIX user provisioning, no chroot: an unprivileged
LXC container is sufficient, the same category of workload as
Network-Manager (an outbound-heavy, no-OS-level-work Go process), not
Storage-Service (which genuinely needs real OS-level capabilities).

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1 vCPU, 256 MB RAM: this process holds nothing in memory beyond one
  MQTT client's connection state and one pgx connection pool - no request
  queue, no per-request buffering beyond a single message at a time.
- Minimal disk: the binary itself, its `migrations/` directory (applied
  once at startup), no persistent local state of its own (all state lives
  in TimescaleDB).

## Network placement (NET-F-01)

Reachable only from the private network this stack's other services and
its two dependencies (the MQTT broker, TimescaleDB) already live on - no
port needs to be exposed to anything outside that private network, since
nothing calls Metrics-Collector; it only calls out.

## Dependencies that must exist first

- The MQTT broker (Mosquitto), reachable at the address
  `RAM_USB_MQTT_BROKER_URL` names, with this process's own dev-only or
  production client certificate/key already provisioned and its ACL grant
  (`third-party/mosquitto/acl.conf`: `user MetricsCollector` / `topic read
  metrics/#`) already in place.
- TimescaleDB, reachable at the address `RAM_USB_METRICS_COLLECTOR_DATABASE_URL`
  names, with the `timescaledb` extension already created (see
  `third-party/timescaledb/init.sql`'s own doc comment for why that step
  happens outside this process's own migrations).

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker.internal:8883` |
| `RAM_USB_MQTT_CLIENT_CERT` / `RAM_USB_MQTT_CLIENT_KEY` | yes | This process's own MQTT client certificate/key pair |
| `RAM_USB_MQTT_CA` | yes | CA bundle (PEM) trusted to have issued the broker's server certificate |
| `RAM_USB_METRICS_COLLECTOR_DATABASE_URL` | yes | TimescaleDB/Postgres connection string |
| `RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR` | no (defaults to the checked-in `services/metrics-collector/migrations` path) | Migration files directory |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure) - unlike every publish-side service, for which the same four
`RAM_USB_MQTT_*` variables are optional, since MQTT is this process's
entire purpose, not a side effect of an otherwise-independent server.

## What a real (non-dev) deployment still needs, not yet decided here

- A production MQTT client certificate issuance/rotation path for this
  process (PKI-F-03 - "should" exist, not yet built for MQTT identities
  at all, dev or production; see `third-party/mosquitto/generate-dev-certs.sh`'s
  own doc comment for the current dev-only judgment call and why MQTT
  identities are deliberately outside `pkg/pki`'s CA-F-04 bootstrap flow).
- Log shipping/monitoring of this process's own health, beyond what
  `slog`'s stdout output provides - out of this task's scope (MT-F-01..04
  cover collecting *other* services' metrics, not observing
  Metrics-Collector itself).
