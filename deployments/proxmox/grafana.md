# Grafana (Metrics-Visualizer): Proxmox deployment notes

Written directly from `deployments/compose/grafana.yml`'s own dev-stack
wiring, `third-party/grafana/provisioning/`'s own datasource/dashboard
files, the SRS's MT-F-04/RU-10/UC-05 text, and
`deployments/proxmox/certificate-authority.md`'s/`mosquitto.md`'s own
mesh-only-reachability precedent, translated to a Proxmox guest instead of
a Compose service - same approach those two docs used. Resolves
`docs/Known_Issues.md`'s KI-11 for this component.

## What this process is

The official `grafana/grafana:13.1` image (MT-F-04), configured entirely
via file-based provisioning - no manual UI setup:

- `third-party/grafana/provisioning/datasources/timescaledb.yaml` wires a
  single fixed-`uid` Postgres datasource pointed at
  `metrics-collector:5432` - TimescaleDB is co-located inside
  Metrics-Collector's own container/guest (KI-18, see `.claude/agent-memory/
  code-agent.md`'s note that Grafana's file-based provisioning does not
  resolve `"${DS_VARNAME}"` template syntax - a fixed `uid:` is required).
  This connection is mTLS (KI-22, RNF-SEC-04, `sslmode: verify-full`) -
  see "mTLS to TimescaleDB" below.
- `third-party/grafana/provisioning/dashboards/dashboards.yaml` +
  `third-party/grafana/dashboards/metrics-overview.json` provision the
  MT-F-04 dashboards (response time, throughput, active connections) at
  container start.
- `GF_SECURITY_ADMIN_USER`/`GF_SECURITY_ADMIN_PASSWORD` set this
  deployment's own admin credentials - no image default is left active
  (RD-04, fail-secure).
- `GF_PLUGINS_PREINSTALL_ASYNC: "false"` disables Grafana's own
  automatic first-start download of ~13 unused "preinstalled" plugins -
  see `deployments/compose/grafana.yml`'s own top comment for why (an
  observed OOM-kill on a memory-constrained dev host), carried forward
  here since nothing about it is dev-stack-specific.

Grafana itself makes exactly one outbound connection (to TimescaleDB) and
serves exactly one inbound consumer: a human Admin's own browser, per
UC-05 ("query on Grafana -> TimescaleDB... filtered by service and metric
name"). Unlike every other RAM-USB service or third-party product covered
by this project's Proxmox docs so far, **Grafana's inbound consumer is not
another RAM-USB service or component** - see "Network placement" below
for why that distinction still does not change the mesh-only-reachability
outcome.

## Network placement and reachability (RU-10, UC-05, NET-F-01)

**Two different connections, two different rules — confirmed directly
with the user, not inferred:**

1. **Admin → Grafana (inbound, UC-05's human consumer)**: `localhost`
   only, via an SSH tunnel into this guest, authenticated by standard SSH
   key access. Grafana's own HTTP listener binds to `127.0.0.1`, never
   the guest's real network interface and never a mesh IP either — there
   is no Tailscale identity, no ACL tag, and no Headscale involvement in
   this path at all. This is simpler than Certificate-Authority's/
   Mosquitto's own "mesh-only" rule, not an extension of it: an SSH
   tunnel is this project's existing, standard operator-access pattern
   (the same way an operator already reaches this guest at all to manage
   it), reused here rather than inventing a parallel Tailscale-based
   admin-access mechanism. This also means Grafana needs **no**
   `ports:` mapping to the guest's public interface (same conclusion as
   `certificate-authority.md`'s "No published ports" rule, reached for a
   different reason: not "mesh-only instead," but "not reachable from
   any network path *or* the mesh - `localhost` only").
2. **Grafana → TimescaleDB (outbound, UC-05's own "query on Grafana ->
   TimescaleDB")**: over the Tailscale mesh, same rule as every other
   cross-guest RAM-USB connection (NET-F-01, RNF-SEC-04) - TimescaleDB is
   co-located inside Metrics-Collector's own container/guest
   (`docs/Known_Issues.md`'s KI-18, `deployments/proxmox/
   metrics-collector.md`), reachable under Metrics-Collector's own mesh
   identity (`tag:metrics-collector`).

Grafana's own guest therefore still needs a `tailscale/tailscale` sidecar
container (now a real Compose service, `deployments/compose/grafana.yml`'s
`grafana-mesh`, sharing Grafana's own network namespace via
`network_mode: "service:grafana"` - the same `certificate-authority-mesh`/
`mqtt-broker-mesh` pattern those two docs already use).

**Correction, live-verified (superseding this doc's own earlier reasoning
below):** `TS_USERSPACE` must be `"false"` here too, exactly like
Certificate-Authority's/Mosquitto's own sidecars - the original reasoning
that it could stay at its default because "Grafana never needs to *accept*
an inbound mesh connection" was wrong. Userspace-networking mode means
`tailscaled` itself has no kernel-visible `tailscale0` interface at all -
only `tailscaled`'s own process can reach the tailnet, through its
internal netstack. Grafana's Postgres driver is a SEPARATE process merely
sharing that network namespace; it has no way to route a real outbound TCP
connection to a `100.64.0.0/10` address through a sidecar in that mode
either, regardless of direction. Confirmed live this session: a `psql`
connection from Grafana's own shared namespace to Metrics-Collector's real
mesh IP got "Connection refused"/timed out with `TS_USERSPACE` at its
default, and succeeded (real mTLS handshake, matching client-certificate
serial visible in TimescaleDB's own `pg_stat_ssl`) once set to `"false"`.
The general rule this revises: `TS_USERSPACE=false` is required whenever
ANY process sharing a sidecar's network namespace (not `tailscaled`
itself) needs to originate OR accept mesh traffic - not only the "accepts
inbound" case this doc originally described.

### What was genuinely undecided here, now resolved

Unlike a User reaching Storage-Service - where NM-F-09 gives a concrete,
already-built mechanism (Network-Manager grants a time-limited ACL tag on
login) - the SRS has no equivalent mechanism for an Admin identity, and
none was needed: the Admin never joins the mesh at all (see point 1
above). No `tag:admin` needed in `services/network-manager/internal/
headscale/policy.go`. Tracked and closed as `docs/Known_Issues.md`'s
KI-17.

## mTLS to TimescaleDB (KI-22, RNF-SEC-04, PKI-F-03)

Grafana's own outbound connection to TimescaleDB is genuine cross-guest
inter-service traffic (UC-05), so RNF-SEC-04's "no exceptions" clause
applies - unlike Metrics-Collector's own same-container loopback
connection to this same database, which stays password-only
(`third-party/timescaledb/pg_hba-mtls.sh`'s own doc comment explains why
that specific exemption is principled, not a loophole).

`deployments/compose/grafana.yml`'s `grafana-cert-issuer`/
`grafana-cert-renewer` mint and keep renewed a client certificate whose
CommonName is exactly `metrics_collector` - the Postgres role Grafana
connects as - because TimescaleDB's `hostssl ... clientcert=verify-full`
pg_hba.conf rule requires the two to match exactly, with no
`pg_ident.conf` mapping layer (YAGNI). The datasource itself
(`third-party/grafana/provisioning/datasources/timescaledb.yaml`) points
`sslmode: verify-full` at three file-path-mounted certificates
(`tlsConfigurationMethod: file-path`, Grafana's own documented mechanism)
- the client cert/key plus the CA root used to verify TimescaleDB's own
server certificate. The `secureJsonData.password` field is KEPT alongside
the client certificate (defense-in-depth, RNF-SEC-02/03), expanded from
the same `RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD` value
`metrics-collector.yml`'s own `POSTGRES_PASSWORD` uses, via Grafana's own
provisioning-file environment-variable expansion.

In this dev Compose stack, `grafana-cert-issuer`/`grafana-cert-renewer`
still reach Certificate-Authority directly over `ramusb-net`, unchanged
(KI-05's own dev-convenience wiring, deliberately left as-is) - a real
production deployment would instead route them over `grafana-mesh`, the
same way `mqtt-broker-cert-renewer` shares `mqtt-broker-mesh`'s namespace.
**Resolved (KI-25, this session)**: `grafana-mesh` is now a real Compose
service, and `tag:grafana` now carries Certificate-Authority reachability
in `services/network-manager/internal/headscale/policy.go`'s NM-F-04
rule, alongside `TagEntryHub`/`TagSecuritySwitch`/`TagDatabaseVault`/
`TagStorageService`/`TagNetworkManager`/`TagMQTTBroker` - confirmed live
via `headscale policy get` after a fresh Network-Manager policy push. The
`tag:grafana` -> `tag:metrics-collector` rule this section's "Dependencies
that must exist first" already documented was live-verified this session
too: a real mTLS `psql` query from inside Grafana's own shared network
namespace to Metrics-Collector's real mesh IP (`100.64.0.14` in this dev
run) succeeded, with `pg_stat_ssl.client_serial` matching Grafana's own
minted certificate exactly.

## LXC vs KVM placement (RNF-ORG-04)

RNF-ORG-04 places Grafana on an **LXC** container ("the other services,"
alongside Security-Switch/Certificate-Authority/Mosquitto - not the KVM
group reserved for Storage-Service/Database-Vault/Network-Manager). Same
reasoning class as those three docs: this guest needs nothing beyond what
the Tailscale mesh sidecar itself requires
(`NET_ADMIN`/`NET_RAW`/`/dev/net/tun`, `TS_USERSPACE=false` - see "Network
placement" above) - Grafana itself does no
POSIX-user provisioning, `chroot`, or raw-socket work of its own. Same
unprivileged-LXC `/dev/net/tun` enablement caveat as the other three docs
(not yet verified against a real Proxmox LXC guest).

## Dependencies that must exist first

- The separately-deployed Headscale/reverse-proxy VPS (NM-F-14), reachable
  at `RAM_USB_TAILSCALE_CONTROL_URL` over the public internet, to mint this
  guest's own single-use Tailscale pre-auth key before the mesh sidecar
  can join.
- TimescaleDB, reachable at the address Grafana's own datasource
  provisioning names. **Resolved** (`docs/Known_Issues.md`'s KI-18):
  TimescaleDB is co-located inside Metrics-Collector's own container/guest
  (`deployments/proxmox/metrics-collector.md`, the same "absorb the
  third-party server into one image" pattern already used for
  Database-Vault+Postgres), reachable over the Tailscale mesh under
  Metrics-Collector's own mesh identity (`tag:metrics-collector`) - not a
  separate guest or mesh identity of its own. Network-Manager's ACL policy
  (`services/network-manager/internal/headscale/policy.go`) grants
  `tag:grafana` reachability toward `tag:metrics-collector` for this
  connection.
- `third-party/grafana/provisioning/datasources/timescaledb.yaml`'s own
  `secureJsonData.password` (currently a dev-only plaintext value,
  `metrics_collector_dev_only`) needs a real secrets-management story
  before production, matching every other component's own "plaintext
  bind-mounted secret" open item.

## Environment variables (see `deployments/compose/grafana.yml` for the dev-stack values this table generalizes)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_GRAFANA_ADMIN_USER` | yes | This deployment's own Grafana admin username - no image default is left active |
| `RAM_USB_GRAFANA_ADMIN_PASSWORD` | yes | This deployment's own Grafana admin password - needs a real secrets-management story in production, not yet decided (same open item as every other component's own plaintext-secret gap) |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | Headscale's real public VPS coordination URL - never a Docker DNS shortcut in production, same as every other mesh-sidecar-carrying component |
| `RAM_USB_GRAFANA_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key for this guest's own mesh sidecar - needed only for Grafana's own outbound connection to TimescaleDB, tagged `tag:grafana` (`services/network-manager/internal/headscale/policy.go`, KI-18) |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- An SSH access-control story for this guest (key management, which
  operators/Admins get a key) - standard Proxmox/Linux operator access,
  not a RAM-USB-specific mechanism, so not detailed further here.
- `RAM_USB_GRAFANA_ADMIN_PASSWORD` and the TimescaleDB datasource's own
  `secureJsonData.password`, both real secrets needing a production
  secrets-management mechanism, not yet decided (same open item every
  other component's own doc already flags for its own plaintext secrets).
- `ramusb-grafana-data`'s durability guarantee at the real Proxmox guest
  level (a persistent disk/volume surviving guest restart, not just
  container restart) - same open item as every other component's Proxmox
  note; loses provisioned-but-modified dashboard state (starred/edited
  views) on loss, though not the provisioned dashboards/datasource
  themselves, which are re-applied from the checked-in
  `third-party/grafana/` files on every start regardless.
- Log shipping/monitoring of this process's own health beyond `docker
  logs`, same open item as every other component's Proxmox note.

## Container sizing (dev/thesis-scale judgment call, not a measured production figure)

- 1 vCPU, 256-512 MB RAM: Grafana's own steady-state load here is a single
  Admin's occasional dashboard queries, not a continuous high-throughput
  data path - the same request-relay-adjacent category as
  Certificate-Authority's own sizing note, plus the mesh sidecar's modest
  footprint.
- Minimal disk: Grafana's own SQLite metadata store (`/var/lib/grafana`,
  dashboard/user/session state) - the actual metrics data lives in
  TimescaleDB, not here.
