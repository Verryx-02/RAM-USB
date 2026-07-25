# Network-Manager: Proxmox deployment notes

Written directly from `services/network-manager/cmd/network-manager/main.go`'s
own package doc comment and `const` block,
`deployments/docker/network-manager/Dockerfile`'s doc comment, and
`deployments/compose/network-manager.yml`'s dev-stack wiring, translated to
a Proxmox guest instead of a Compose service - same approach
`metrics-collector.md` used, since (as of this writing) no other
`deployments/proxmox/*.md` file exists yet to mirror instead.

## What this process is

Two independent long-lived processes, s6-overlay-supervised on a
`debian:bookworm-slim` base: a real OS-level `tailscaled` client for
private-mesh membership, and Network-Manager's own Go mTLS HTTP server
(NM-F-03's connection-acceptance TLS config, NM-F-08's mesh-user creation,
NM-F-09's storage-access grant). It also runs NM-F-10's periodic expiry
sweep against its own SQLite grant store (NM-F-11), and publishes
aggregated metrics every minute (NM-F-17/NM-F-18).

**Headscale is not co-located here.** An earlier design ran Headscale
inside this same container, reached over loopback gRPC; that was
withdrawn after finding Headscale's own documented limitation
(headscale.net's FAQ): "running headscale on a machine that is also in
the tailnet it coordinates... is not supported." Headscale's coordination
server can never safely be a member of the mesh it coordinates. Headscale
is now its own fully separate deployment (`deployments/compose/
headscale.yml`, `deployments/docker/headscale/` - a reverse proxy plus
Headscale itself, no Network-Manager code at all - see
`deployments/vps/headscale.md` for its own standalone-VPS deployment
notes). Network-Manager is now a regular mesh-joined service, structurally
identical to Security-Switch's own container: its inbound mTLS listener
(NM-F-03) is mesh-only, and every NM-F-08/NM-F-09/NM-F-10/NM-F-01..07
Headscale-administration call goes out via a REST client
(`net/http`, `services/network-manager/internal/headscale/client.go` and
`rest.go` - no gRPC anymore) over the **public** network, through
Headscale's reverse proxy, presenting this process's own mTLS client
certificate (`organization=NetworkManager`, NM-F-12) plus a bearer API
key layered on top. This is the one call in the entire system that
crosses the public network instead of the private mesh - a deliberate,
accepted architectural exception forced by Headscale's own limitation
(see `main.go`'s own package doc comment for the full reasoning), not an
oversight.

`tailscaled` is a real OS-level client here, not `pkg/mesh`'s in-process
`tsnet`, for the identical reason documented in
`deployments/proxmox/security-switch.md`: neither `pkg/pki`'s
CA-bootstrap/renewal traffic nor `pkg/metrics`' MQTT-publish traffic can
be routed through an in-process-only netstack.

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1 vCPU, 512 MB-1 GB RAM: same request-relay category as
  Security-Switch's own sizing note, plus `tailscaled`'s modest
  steady-state footprint and a small SQLite grant store (NM-F-11) held on
  local disk, not in memory.
- Minimal disk beyond the Go binary and `tailscaled`'s own binary: the
  grants SQLite database (`RAM_USB_NETWORK_MANAGER_GRANTS_DB_PATH`) grows
  with active grant count, not with any user-facing content - each row is
  an email-to-pre-auth-key-ID mapping and a 12-hour expiry, not backup
  data.

## Network placement (NET-F-01, NM-F-12, NM-F-14, RNF-ORG-04)

RNF-ORG-04 places Network-Manager on a **KVM** guest (grouped with
Storage-Service and Database-Vault - see
`deployments/proxmox/database-vault.md`'s own placement reasoning for why
a full VM suits `tailscaled`'s kernel-network-interface need better than
an unprivileged LXC guest).

Two genuinely different reachability rules apply to this one guest:
- Its own mTLS listener (NM-F-03, accepting only Security-Switch,
  NM-F-01's allow-list) binds exclusively to this node's real Tailscale
  mesh interface address, assembled at container start - never `0.0.0.0`
  (NET-F-01).
- Its outbound Headscale-admin REST calls (NM-F-08/09/10/12) cross the
  **public** network to reach the separately-deployed Headscale/reverse-
  proxy container - NM-F-12's own SRS note explains why this one call
  cannot be restricted by network placement at all, unlike every other
  inter-service call in this system: "Headscale's own documentation
  advises against making the coordination server itself a member of the
  mesh it coordinates, so... this admin traffic cannot be restricted by
  network placement; it is reachable over the same public network as
  NM-F-14's coordination endpoint, with mTLS (RNF-SEC-04) as the sole
  enforcement layer." This guest therefore needs a real route to the
  public network/internet in addition to its mesh interface - not just
  the private cluster network the other two KVM-placed services need.

## Dependencies that must exist first

- Certificate-Authority, reachable to mint this service's single-use
  bootstrap token (`RAM_USB_CA_BOOTSTRAP_TOKEN`, CA-F-04).
- The separately-deployed Headscale/reverse-proxy container
  (`deployments/compose/headscale.yml`, ideally its own dedicated
  publicly-addressable VPS per NM-F-14 in production - ONLY this dev/test
  Compose stack runs it on the shared Docker host), reachable at:
  - `RAM_USB_TAILSCALE_CONTROL_URL`, to mint this node's own single-use
    Tailscale pre-auth key (`RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY`,
    tagged `tag:network-manager`) before this container's own
    `tailscaled` can join the mesh, and
  - `RAM_USB_NETWORK_MANAGER_HEADSCALE_API_URL`, Headscale's own admin
    REST API, authenticated with a bearer API key
    (`RAM_USB_NETWORK_MANAGER_HEADSCALE_API_KEY`, minted out-of-band on
    the Headscale container itself, e.g. `headscale apikeys create`) and
    this process's own mTLS client certificate.
- The MQTT broker (Mosquitto), reachable at `RAM_USB_MQTT_BROKER_URL`,
  with this service's ACL grant already in place (NM-F-17).

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_NETWORK_MANAGER_LISTEN_ADDR` | yes | Real host:port this server listens on for Security-Switch's inbound mTLS connections (NM-F-03); assembled at container start from this node's real Tailscale IPv4 plus a port (the dev Compose file sets only the port half, `RAM_USB_NETWORK_MANAGER_LISTEN_PORT: "8447"`) |
| `RAM_USB_NETWORK_MANAGER_HEADSCALE_API_URL` | yes | The **public** base URL of the reverse proxy fronting the separately-deployed Headscale instance, e.g. `https://headscale.example:8080` in production, `https://headscale:8080` in the dev Compose stack |
| `RAM_USB_NETWORK_MANAGER_HEADSCALE_API_KEY` | yes | Headscale's own bearer API key, minted out-of-band on the Headscale container/VPS itself |
| `RAM_USB_NETWORK_MANAGER_HEADSCALE_API_CA_FILE` | no (dev-only) | Trusts the reverse proxy's own self-signed public-facing certificate - **never** RAM-USB's internal Certificate-Authority (a deliberately different trust root, since real end-user Tailscale clients must trust this certificate too); leave unset once that certificate chains to a real, publicly trusted root (e.g. Let's Encrypt in production) |
| `RAM_USB_NETWORK_MANAGER_GRANTS_DB_PATH` | yes | Filesystem path to NM-F-11's SQLite grant store; required (not defaulted) so an operator-chosen, durable path is always explicit (RD-04, fail-secure) |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA bootstrap token (CA-F-04) for this process's one identity |
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker:8883` (NM-F-17) |
| `RAM_USB_NETWORK_MANAGER_MESH_HOSTNAME` | yes | This node's MagicDNS short name within the Headscale mesh |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | The Headscale coordination URL - the separately-deployed `headscale` container/VPS (this process's own mesh join, distinct from its Headscale-admin-API calls above) |
| `RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:network-manager` |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- A production Headscale API-key rotation procedure, distinct from
  Security-Switch's CA-bootstrap-token rotation open item (PKI-F-03).
- `RAM_USB_NETWORK_MANAGER_GRANTS_DB_PATH`'s own durability guarantee at
  the real Proxmox guest level (a persistent disk/volume surviving guest
  restart, not just container restart) - not yet decided beyond the dev
  Compose stack's own bind mount.
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other service's Proxmox note.

## Headscale's own deployment notes live under `deployments/vps/`

Headscale is deliberately **not** part of the Proxmox cluster at all -
NM-F-14 places it "ideally hosted on its own publicly-addressable VPS,"
and `deployments/compose/headscale.yml`'s own top comment states this
explicitly ("kept here as a real container for local dev/test only"). Its
own deployment notes are `deployments/vps/headscale.md`, alongside
Entry-Hub's (`deployments/vps/entry-hub.md`) - the other RAM-USB component
NET-F-01 places outside the private Proxmox cluster - not a file under
this `deployments/proxmox/` directory, which would misstate where
Headscale actually runs in production.
