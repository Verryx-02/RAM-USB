# Database-Vault: Proxmox deployment notes

Written directly from `services/database-vault/cmd/database-vault/main.go`'s
own package doc comment and `const` block,
`deployments/docker/database-vault/Dockerfile`'s doc comment, and
`deployments/compose/database-vault.yml`'s dev-stack wiring, translated to
a Proxmox guest instead of a Compose service - same approach
`metrics-collector.md` used, since (as of this writing) no other
`deployments/proxmox/*.md` file exists yet to mirror instead.

## What this process is

Database-Vault is literally the vault: Postgres is merged into this same
image (built FROM `postgres:17`, not a separate container with a network
dependency on one) and supervised by s6-overlay alongside the
database-vault Go binary, plus a real OS-level `tailscaled` client for
private-mesh membership - three long-lived processes in one guest.
Postgres binds to loopback only (`-c listen_addresses=localhost`, passed
through `postgres:17`'s own entrypoint) - reachable from nothing but this
container's own Go process, closing a gap the SRS does not explicitly name
but that this project treats as a genuine requirement given
Database-Vault's role (DV-F-08).

The Go binary itself implements DV-F-01..DV-F-20: two mTLS listeners (one
for Security-Switch's register/login traffic over the mesh, DV-F-01; one
for Storage-Service's ST-F-11 public-key lookup, kept on the private
network rather than the mesh), an outbound mTLS client to Storage-Service
(DV-F-09), Argon2id password hashing (DV-F-07) and AES-256-GCM/HKDF email
encryption (DV-F-04) using the master key and pepper (DV-F-05/DV-F-06), an
automatic schema-migration step at startup, and DV-F-16/DV-F-17's periodic
metrics publish.

`tailscaled` is a real OS-level client here, not `pkg/mesh`'s in-process
`tsnet`, for the identical reason documented in
`deployments/proxmox/security-switch.md`: neither `pkg/pki`'s
CA-bootstrap/renewal traffic nor `pkg/metrics`' MQTT-publish traffic can be
routed through an in-process-only netstack (see
`.claude/agent-memory/code-agent.md`'s "pkg/pki dialer routing" section).

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 2 vCPU, 2-4 GB RAM: this is the one service in this group that is
  genuinely resource-heavier than a plain request-relay - it runs a real
  Postgres instance (its own shared buffers, WAL, connection handling) in
  addition to `pgxpool`'s connection pool on the Go side, and Argon2id's
  own cost parameters (DV-F-07: 47104 KiB / 46 MiB memory, per hash
  computation) mean concurrent login/registration traffic has a real,
  deliberately-expensive per-request memory cost, not just CPU cost.
- Disk grows with the user table (DV-F-08's records) and Postgres's own
  WAL/index overhead - modest at thesis scale (email hash + encrypted
  email + Argon2id hash string per user, no file content ever stored
  here per RNF-SEC-01), but this is the one Proxmox note in this group
  where disk sizing should be revisited as the user base grows, unlike
  Security-Switch/Network-Manager which hold no durable records of their
  own beyond mesh identity.

## Network placement (NET-F-01, RNF-ORG-04)

RNF-ORG-04 places Database-Vault on a **KVM** guest (grouped with
Storage-Service and Network-Manager). A full VM gives `tailscaled` a
genuine kernel network interface without the unprivileged-LXC
`/dev/net/tun` passthrough complication documented for Security-Switch's
own LXC placement - consistent with why the other two KVM-placed services
also need a real kernel network stack (Storage-Service's sshd; Network-
Manager's own `tailscaled`, joining the same mesh).

Two separate listeners, two separate reachability rules:
- The register/login listener (`RAM_USB_DATABASE_VAULT_LISTEN_ADDR`,
  DV-F-01) binds exclusively to this node's real Tailscale mesh interface
  address, assembled at container start (never `0.0.0.0`, NET-F-01) -
  reachable only from Security-Switch per NM-F-02's allow-list.
- The public-key listener (`RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR`,
  ST-F-11) stays on the private network rather than the mesh interface
  (`0.0.0.0:8446` in the dev Compose file, reachable via the guest's own
  private-network attachment) - Storage-Service's `AuthorizedKeysCommand`
  binary calls this on every SFTP connection attempt.

Postgres itself is never exposed beyond loopback - no Proxmox-level
network exposure decision applies to it at all.

## Dependencies that must exist first

- Certificate-Authority, reachable to mint this service's single-use
  bootstrap token (`RAM_USB_CA_BOOTSTRAP_TOKEN`, CA-F-04).
- The separately-deployed Headscale/reverse-proxy container
  (`deployments/compose/headscale.yml`), reachable at
  `RAM_USB_TAILSCALE_CONTROL_URL` to mint this node's single-use Tailscale
  pre-auth key (`RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY`, tagged
  `tag:database-vault`) before this container's own `tailscaled` can join
  the mesh.
- Storage-Service, reachable at `RAM_USB_STORAGE_SERVICE_URL` over the
  mesh once joined (DV-F-09).
- The MQTT broker (Mosquitto), reachable at `RAM_USB_MQTT_BROKER_URL`,
  with this service's ACL grant already in place (DV-F-16).
- `RAM_USB_MASTER_KEY` and `RAM_USB_PASSWORD_PEPPER` distributed
  out-of-band to the operator before first start (DV-F-05/DV-F-06, RD-02:
  these values, and every key HKDF derives from them, must never be
  persisted anywhere other than this process's own memory for the
  duration of the operation that needs them).

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_DATABASE_VAULT_LISTEN_ADDR` | yes | Real host:port for the register/login mTLS listener (DV-F-01); assembled at container start from this node's real Tailscale IPv4 plus a port (the dev Compose file sets only the port half, `RAM_USB_DATABASE_VAULT_LISTEN_PORT: "8445"`) |
| `RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR` | yes | Address for ST-F-11's public-key lookup listener, kept on the private network rather than the mesh (dev default `0.0.0.0:8446`) |
| `RAM_USB_DATABASE_VAULT_DATABASE_URL` | yes | Postgres connection string, e.g. `postgres://database_vault:<password>@localhost:5432/database_vault?sslmode=disable` (loopback host, since Postgres is merged into this same container) |
| `RAM_USB_DATABASE_VAULT_MIGRATIONS_DIR` | no (defaults to the checked-in `services/database-vault/migrations` path) | Migration files directory, applied once at startup before this process accepts connections |
| `RAM_USB_STORAGE_SERVICE_URL` | yes | Storage-Service's base URL, e.g. `https://storage-service:8448`, resolved over the mesh (DV-F-09) |
| `RAM_USB_MASTER_KEY` | yes | 32-byte master key for HKDF-derived per-record email-encryption keys (DV-F-04/DV-F-05) |
| `RAM_USB_PASSWORD_PEPPER` | yes | Pepper mixed into every Argon2id computation (DV-F-06/DV-F-07) |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA bootstrap token (CA-F-04); reused for both inbound listeners and the outbound Storage-Service client |
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker:8883` (DV-F-16) |
| `RAM_USB_DATABASE_VAULT_MESH_HOSTNAME` | yes | This node's MagicDNS short name within the Headscale mesh |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | The Headscale coordination URL - the separately-deployed `headscale` container/VPS |
| `RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:database-vault` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | Consumed directly by the merged `postgres:17` entrypoint on first init; `POSTGRES_PASSWORD` must match the password embedded in `RAM_USB_DATABASE_VAULT_DATABASE_URL` above and only takes effect on an empty data directory |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- DV-F-18/DV-F-19: a master-key backup procedure and a master-key rotation
  procedure both "should" exist per the SRS but are not yet built (RD-02
  constrains any future design here: HKDF-derived keys themselves must
  never be persisted).
- A Postgres backup/point-in-time-recovery procedure for the merged
  database itself - not covered by any current requirement ID, and not
  yet decided.
- A production Tailscale pre-auth-key / CA-bootstrap-token minting and
  rotation procedure, same open item as Security-Switch's own note
  (PKI-F-03).
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other service's Proxmox note.
