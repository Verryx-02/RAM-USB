# Security-Switch: Proxmox deployment notes

Written directly from `services/security-switch/cmd/security-switch/main.go`'s
own package doc comment and `const` block,
`deployments/docker/security-switch/Dockerfile`'s doc comment, and
`deployments/compose/security-switch.yml`'s dev-stack wiring, translated to
a Proxmox guest instead of a Compose service - same approach
`metrics-collector.md` used, since (as of this writing) no other
`deployments/proxmox/*.md` file exists yet to mirror instead.

## What this process is

Two independent long-lived processes, s6-overlay-supervised on a
`debian:bookworm-slim` base (see the Dockerfile's own doc comment): a real
OS-level `tailscaled` client for private-mesh membership, and
Security-Switch's own Go mTLS HTTP server implementing SS-F-01..09. No
sshd, no POSIX-user provisioning, no chroot - this is a pure
request-relay: it accepts an mTLS connection from Entry-Hub only
(SS-F-01), re-validates the input independently (SS-F-02), forwards it to
Database-Vault (SS-F-04), and, on Database-Vault's confirmation, calls
Network-Manager either to grant 12-hour Storage-Service reachability
(SS-F-05, login) or to create the new account's mesh user and pre-auth key
(SS-F-09, registration) - then publishes aggregated, PII-free metrics
every minute (SS-F-07/SS-F-08).

`tailscaled` is a real OS-level client here because neither `pkg/pki`'s
CA-bootstrap/renewal traffic nor `pkg/metrics`' MQTT-publish traffic can be
routed through an in-process-only netstack (confirmed library limitation,
not a code gap - see
`.claude/agent-memory/code-agent.md`'s "pkg/pki dialer routing" section). A
genuine kernel `tailscale0` interface forces every outbound connection this
process makes through the mesh automatically, including those two
libraries' own internal calls, with zero application-level dial injection.

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1 vCPU, 256-512 MB RAM: the same request-relay category as
  Metrics-Collector's own sizing note (no request queue, no per-request
  buffering beyond one in-flight relay at a time), plus `tailscaled`'s own
  modest steady-state footprint (a real userspace WireGuard/netstack
  process, not just a Go HTTP handler).
- Minimal disk: the Go binary, `tailscaled`'s own binary, and no
  persistent local state of its own beyond the mesh identity
  (`/var/lib/tailscale`, backed by the `ramusb-security-switch-mesh-state`
  volume in the dev Compose stack) - Security-Switch holds no database and
  no user files.

## Network placement (NET-F-01, RNF-ORG-04)

RNF-ORG-04 places Security-Switch on an **LXC** container (grouped with
"the other services," distinct from Storage-Service/Database-Vault/
Network-Manager's KVM placement). Its inbound mTLS listener (SS-F-01)
binds exclusively to this node's real Tailscale mesh interface address -
assembled at container start from the node's actual Tailscale IPv4 (never
`0.0.0.0` or a Docker-bridge-style address, NET-F-01) - so the LXC guest
needs the same effective privileges the dev Compose stack grants its
Docker container (`cap_add: [NET_ADMIN, NET_RAW]`, `/dev/net/tun`). An
**unprivileged** Proxmox LXC guest needs `/dev/net/tun` enabled explicitly
in the guest's config, by appending to `/etc/pve/lxc/<vmid>.conf` (guest
stopped/started to apply):

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0
```

That produces a working `/dev/net/tun` device node inside the guest. A
Docker container inside that guest, given `--cap-add NET_ADMIN --cap-add
NET_RAW --device /dev/net/tun` plus `TS_USERSPACE=false`, then brings up a
**real kernel** `tailscale0` interface. Confirmed live on 2026-07-31
against Certificate-Authority's own guest (CTID 102, the same
unprivileged-LXC shape this service uses), via `ip link show` from inside
the container - the interface is created before control-server
registration, so this check holds even pointed at an unreachable control
URL, and needs no real Headscale. A guest running this stack's Docker
image rather than the Go binary and `tailscaled` directly may additionally
need the `keyctl`/`nesting` guest features.

Once joined, this node is reachable only by NM-F-01's allow-list (Entry-
Hub, Database-Vault, Network-Manager, Certificate-Authority), enforced at
the mesh ACL layer by Network-Manager's `buildACLs`
(`services/network-manager/internal/headscale/policy.go`), not by
anything in this container itself.

## Dependencies that must exist first

- Certificate-Authority, reachable to mint this service's single-use
  bootstrap token (`RAM_USB_CA_BOOTSTRAP_TOKEN`, CA-F-04) - see
  `deployments/compose/security-switch.yml`'s own
  `docker exec certificate-authority step ca token SecuritySwitch ...`
  comment for the exact dev minting command.
- The separately-deployed Headscale/reverse-proxy container
  (`deployments/compose/headscale.yml`, `deployments/docker/headscale/`),
  reachable at `RAM_USB_TAILSCALE_CONTROL_URL` to mint this node's
  single-use Tailscale pre-auth key
  (`RAM_USB_SECURITY_SWITCH_TAILSCALE_AUTHKEY`, tagged
  `tag:security-switch` per Network-Manager's ACL policy) before this
  container's own `tailscaled` can join the mesh at all.
- Database-Vault, reachable at `RAM_USB_DATABASE_VAULT_URL` over the mesh
  once joined (SS-F-04).
- Network-Manager, reachable at `RAM_USB_NETWORK_MANAGER_URL` over the
  mesh once joined (SS-F-05, SS-F-09).
- The MQTT broker (Mosquitto), reachable at `RAM_USB_MQTT_BROKER_URL`,
  with this service's ACL grant already in place (SS-F-07).

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_SECURITY_SWITCH_LISTEN_ADDR` | yes | Real host:port this server listens on for Entry-Hub's inbound mTLS connections (SS-F-01); assembled at container start from this node's real Tailscale IPv4 plus a port (the dev Compose file sets only the port half, `RAM_USB_SECURITY_SWITCH_LISTEN_PORT: "8444"`) |
| `RAM_USB_DATABASE_VAULT_URL` | yes | Database-Vault's base URL, e.g. `https://database-vault:8445`, resolved via MagicDNS over the mesh (SS-F-04) |
| `RAM_USB_NETWORK_MANAGER_URL` | yes | Network-Manager's base URL, e.g. `https://network-manager:8447`, resolved via MagicDNS over the mesh (SS-F-05, SS-F-09) |
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker:8883` (SS-F-07); this server's MQTT identity is the same bootstrapped mTLS identity reused for everything else, no separate client cert/key |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA bootstrap token (CA-F-04); reused for the inbound listener and both outbound clients (Database-Vault, Network-Manager) |
| `RAM_USB_SECURITY_SWITCH_MESH_HOSTNAME` | yes | This node's MagicDNS short name within the Headscale mesh |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | The Headscale coordination URL - the separately-deployed `headscale` container/VPS, **not** Network-Manager itself (see this file's "What this process is" section) |
| `RAM_USB_SECURITY_SWITCH_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:security-switch` |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- A production Tailscale pre-auth-key / CA-bootstrap-token minting and
  rotation procedure, beyond the dev `docker exec` one-liners documented
  as inline comments in `deployments/compose/security-switch.yml`
  (PKI-F-03 - "should" exist).
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other service's Proxmox note.

**Confirmed live, 2026-07-31** (on Certificate-Authority's own guest,
CTID 102, same unprivileged-LXC shape this service uses): an unprivileged
Proxmox LXC guest does *not* have `/dev/net/tun` by default, but granting
it explicitly at the guest-config level -

```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0
```

(appended to `/etc/pve/lxc/<vmid>.conf`, guest stopped/started to apply) -
produces a working `/dev/net/tun` device node inside the guest. A Docker
container inside that guest, given `--cap-add NET_ADMIN --cap-add
NET_RAW --device /dev/net/tun` plus `TS_USERSPACE=false`, then
successfully brings up a **real kernel** `tailscale0` interface (not the
userspace-netstack fallback) - confirmed via `ip link show` from inside
the container, even pointed at an unreachable/fake control-server URL
(interface creation happens before control-server registration, so this
doesn't require a real Headscale to verify). This closes the "not yet
verified against a real Proxmox LXC guest" gap this section used to
flag.
