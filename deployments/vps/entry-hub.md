# Entry-Hub: VPS deployment notes

Written directly from `services/entry-hub/cmd/entry-hub/main.go`'s own
package doc comment and `const` block,
`deployments/docker/entry-hub/Dockerfile`'s doc comment, and
`deployments/compose/entry-hub.yml`'s dev-stack wiring, translated to a
standalone public VPS guest instead of a Compose service - same approach
`metrics-collector.md`/`security-switch.md`/`database-vault.md`/
`network-manager.md` used for their own Proxmox notes.

This file lives under `deployments/vps/`, not `deployments/proxmox/`,
because Entry-Hub is - together with Headscale (`deployments/vps/
headscale.md`) - one of only two RAM-USB components deliberately **not**
placed on the private Proxmox cluster (see NET-F-01: "Entry-Hub's public
endpoints and Network-Manager's Headscale coordination endpoint (NM-F-14)
are the system's only deliberately public-facing surfaces"). Both need a
real internet-routable public IP and their own publicly trusted TLS
certificate (Let's Encrypt) - a private Proxmox cluster guest, reachable
only over the internal mesh/cluster network, cannot serve that role.

## What this process is

A single Go binary with no OS-level work at all (no sshd, no POSIX-user
provisioning, no chroot, no real kernel TUN device): it binds two TLS
listeners on the SAME public-Let's-Encrypt-issued certificate/key pair -

- a real host-level public socket (`RAM_USB_ENTRY_HUB_LISTEN_ADDR`,
  NET-F-01) serving EH-F-01 (`POST /api/health`) and EH-F-02
  (`POST /api/register`), reachable by anyone, since unauthenticated
  registration must be reachable before a client has ever joined the
  private mesh, and
- a mesh-only listener (`RAM_USB_ENTRY_HUB_LOGIN_LISTEN_ADDR`, via
  `pkg/mesh`'s in-process `tsnet`) serving EH-F-03
  (`POST /api/login`) - reachable only once a client has already
  completed registration and its own mesh join (CL-F-04), removing a
  whole class of unauthenticated-login-endpoint exposure (see `main.go`'s
  own package doc comment, "Listener topology," for the full reasoning) -

plus one outbound mTLS client to Security-Switch (EH-F-07, over the mesh)
and EH-F-10/EH-F-11's periodic MQTT metrics publish (also over the mesh,
reusing the same bootstrapped identity).

Entry-Hub is the one mesh-joined RAM-USB service that stays on `pkg/mesh`'s
in-process `tsnet` rather than a real OS-level `tailscaled` (unlike
Security-Switch/Database-Vault/Storage-Service/Network-Manager - see
`.claude/agent-memory/code-agent.md`'s "pkg/mesh" entry): it holds no
server role toward the Certificate-Authority (`pki.NewClient` only, never
`pki.NewServer`), so its one CA-bootstrapped identity, its outbound
Security-Switch calls, and its MQTT metrics connection can all be routed
through `meshNode.Dial` with no library limitation standing in the way -
no `NET_ADMIN`/`NET_RAW` capability or `/dev/net/tun` device is needed on
this guest for mesh membership itself.

## Container/guest sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1 vCPU, 256-512 MB RAM: the same request-relay category as
  Security-Switch's own sizing note (no request queue, no per-request
  buffering beyond one in-flight relay at a time) - `pkg/mesh`'s in-process
  `tsnet` adds a modest userspace-netstack footprint, smaller than a real
  `tailscaled` process since it runs no kernel WireGuard interface.
- Minimal disk: the Go binary and no persistent local state of its own
  beyond the `tsnet` mesh identity directory (`RAM_USB_ENTRY_HUB_MESH_DIR`,
  backed by the `ramusb-entry-hub-mesh-state` volume in the dev Compose
  stack) - Entry-Hub holds no database and no user files (RNF-SEC-01: it
  never sees backup plaintext at all).

## Network placement (NET-F-01, EH-F-01/EH-F-02/EH-F-03)

Unlike every other RAM-USB service, Entry-Hub is not grouped by RNF-ORG-04's
Proxmox KVM/LXC split at all - it runs on its own dedicated,
publicly-addressable VPS, outside the private Proxmox cluster entirely,
alongside Headscale (`deployments/vps/headscale.md`) but on a **separate**
VPS from it: Entry-Hub is a real mesh member (`pkg/mesh`), and Headscale's
own documented limitation forbids it from ever sharing a host/network
identity with a member of the mesh it coordinates (see
`deployments/vps/headscale.md`'s own placement reasoning).

Two genuinely different reachability rules apply to this one guest, matching
its two listeners:

- `RAM_USB_ENTRY_HUB_LISTEN_ADDR` (EH-F-01/EH-F-02) binds to a real
  public interface address on this VPS, reachable from the open internet -
  the deliberate exception NET-F-01 names for Entry-Hub specifically.
- `RAM_USB_ENTRY_HUB_LOGIN_LISTEN_ADDR` (EH-F-03) is reachable only via
  `pkg/mesh`'s own userspace `tsnet` netstack, never this VPS's public
  network interface - a client must already be a mesh member (post-
  registration, post-CL-F-04) to reach it at all, enforced by `tsnet`
  itself rather than by any Network-Manager ACL rule (Entry-Hub carries no
  `tag:` restricting which mesh peers may dial it, since login is only
  ever called by an already-registered client, not another RAM-USB
  service).
- This guest also needs a real route to the public network/internet at
  process startup, for `pkg/pki`'s very first CA-bootstrap-token exchange
  (no interceptable dial path exists for that one call - see `main.go`'s
  own package doc comment) and to reach Headscale's own public coordination
  endpoint (NM-F-14) to obtain its pre-auth key and join the mesh in the
  first place.

## Dependencies that must exist first

- Certificate-Authority, reachable to mint this service's single-use
  bootstrap token (`RAM_USB_CA_BOOTSTRAP_TOKEN`, CA-F-04) - see
  `deployments/compose/entry-hub.yml`'s own
  `docker exec certificate-authority step ca token EntryHub ...` comment
  for the exact dev minting command.
- The separately-deployed Headscale/reverse-proxy VPS
  (`deployments/vps/headscale.md`), reachable at
  `RAM_USB_TAILSCALE_CONTROL_URL` to mint this node's single-use Tailscale
  pre-auth key (`RAM_USB_ENTRY_HUB_TAILSCALE_AUTHKEY`, tagged
  `tag:entry-hub` per Network-Manager's ACL policy,
  `services/network-manager/internal/headscale/policy.go`) before this
  process's own `pkg/mesh` node can join the mesh at all.
- Security-Switch, reachable at `RAM_USB_SECURITY_SWITCH_URL` over the
  mesh once joined (EH-F-07).
- The MQTT broker (Mosquitto), reachable at `RAM_USB_MQTT_BROKER_URL` over
  the mesh once joined, with this service's ACL grant already in place
  (EH-F-10).
- A real, publicly resolvable DNS record for this VPS pointing at its
  Let's Encrypt-issued certificate's hostname, plus an operator-managed
  ACME client (outside this process's own scope - it loads a certificate/
  key file pair, it does not run ACME itself) keeping
  `RAM_USB_ENTRY_HUB_TLS_CERT`/`RAM_USB_ENTRY_HUB_TLS_KEY` current.

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_ENTRY_HUB_LISTEN_ADDR` | yes | Real public host:port this server's non-mesh listener binds for EH-F-01/EH-F-02 (NET-F-01), e.g. `0.0.0.0:8443` |
| `RAM_USB_ENTRY_HUB_TLS_CERT` / `RAM_USB_ENTRY_HUB_TLS_KEY` | yes | This server's own TLS certificate/key pair, presented on BOTH listeners - Let's Encrypt-issued in production (EH-F-01/EH-F-02/EH-F-03's own literal requirement), a dev-only self-signed pair for local Compose testing |
| `RAM_USB_ENTRY_HUB_LOGIN_LISTEN_ADDR` | yes | A bare `:port` (`tsnet.Server.Listen` only ever announces on this node's own mesh address) this server's mesh-only login listener (EH-F-03) binds |
| `RAM_USB_ENTRY_HUB_MESH_DIR` | yes | This node's persistent `tsnet` mesh identity/state directory |
| `RAM_USB_ENTRY_HUB_MESH_HOSTNAME` | yes | This node's MagicDNS short name within the Headscale mesh |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | The Headscale coordination URL - the separately-deployed `headscale` VPS (`deployments/vps/headscale.md`) |
| `RAM_USB_ENTRY_HUB_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:entry-hub` |
| `RAM_USB_TAILSCALE_CONTROL_CA_FILE` | no (dev-only) | Trusts Headscale's own dev-only self-signed control-plane certificate (`pkg/mesh.Config.ControlCAFile`); leave unset once that certificate chains to a real, publicly trusted root |
| `RAM_USB_SECURITY_SWITCH_URL` | yes | Security-Switch's base URL, e.g. `https://security-switch:8444`, resolved via MagicDNS over the mesh (EH-F-07) |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA bootstrap token (CA-F-04) for this process's one outbound mTLS identity, also reused for EH-F-10/EH-F-11's MQTT connection |
| `RAM_USB_MQTT_BROKER_URL` | no | MQTT broker address, e.g. `tls://mqtt-broker:8883` (EH-F-10/EH-F-11); unlike every other required variable, metrics publishing is simply disabled (with a logged warning) if left unset - Entry-Hub still relays registration/login traffic without it |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- A production ACME client (Let's Encrypt) actually managing
  `RAM_USB_ENTRY_HUB_TLS_CERT`/`RAM_USB_ENTRY_HUB_TLS_KEY`'s renewal on
  this VPS - only a dev-only self-signed pair
  (`third-party/entry-hub/generate-dev-cert.sh`) has been exercised so
  far.
- Firewall/hardening for the one genuinely public listener on this VPS
  (`RAM_USB_ENTRY_HUB_LISTEN_ADDR`) - beyond RNF-SEC-03's application-level
  input re-validation (EH-F-04/EH-F-05/EH-F-06), no network-level
  rate-limiting/DDoS mitigation is decided here.
- A production Tailscale pre-auth-key / CA-bootstrap-token minting and
  rotation procedure, same open item as every other mesh-joined service's
  own deployment note (PKI-F-03 - "should" exist).
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other service's deployment note.
