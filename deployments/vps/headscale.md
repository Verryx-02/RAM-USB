# Headscale: VPS deployment notes

Written directly from `deployments/docker/headscale/Dockerfile`'s own
package doc comment, `deployments/docker/headscale/nginx.conf`'s own doc
comment, and `deployments/compose/headscale.yml`'s dev-stack wiring,
translated to a standalone public VPS guest instead of a Compose service -
same approach `metrics-collector.md`/`security-switch.md`/
`database-vault.md`/`network-manager.md` used for their own Proxmox notes.

This file lives under `deployments/vps/`, not `deployments/proxmox/`,
because Headscale is - together with Entry-Hub (`deployments/vps/
entry-hub.md`) - one of only two RAM-USB components deliberately **not**
placed on the private Proxmox cluster. NM-F-14 states this explicitly:
Headscale's coordination endpoint is "ideally hosted on its own
publicly-addressable VPS." This is not merely a preference: headscale.net's
own FAQ documents a hard limitation - "running headscale on a machine that
is also in the tailnet it coordinates... is not supported" - so Headscale
can never itself be a member of the private mesh it coordinates, and
therefore can never be co-located with any RAM-USB mesh-joined service
(`deployments/proxmox/network-manager.md` documents the earlier,
since-withdrawn design that tried exactly that). `deployments/compose/
headscale.yml`'s own top comment states the dev/test Compose stack keeps it
on the shared Docker host purely for local convenience, not as a model for
production placement.

Headscale is deployed on its **own separate VPS from Entry-Hub**, even
though both are "public, non-Proxmox" components: Entry-Hub is a real mesh
member (`pkg/mesh`), and the limitation above forbids sharing a host with
one.

## What this process is

TWO long-lived processes, s6-overlay-supervised on a `debian:bookworm-slim`
base - Headscale itself (the official `headscale/headscale` binary,
loopback-only, `127.0.0.1:8081`, plain HTTP) and an nginx reverse proxy
(the only thing this container exposes to the network, `0.0.0.0:8080`).
No RAM-USB Go code runs here at all, and this container holds no RAM-USB
mTLS identity of its own (no CA bootstrap token) - it is the one container
in this project's stack that is neither a mesh member nor a
Certificate-Authority-bootstrapped service.

Headscale does not separate its coordination protocol from its NM-F-12
admin REST surface (`/api/v1/*`) by listener - both are served on the exact
same `net.Listener` (confirmed by reading
`github.com/juanfont/headscale@v0.29.2`'s `hscontrol/app.go`; its separate
gRPC listener has no path structure to distinguish requests by at all, and
this project's Network-Manager no longer uses it). nginx is what makes the
resulting per-path split possible:

- `/api/v1/*` (NM-F-12): requires a valid mTLS client certificate, chained
  to RAM-USB's internal Certificate-Authority root, whose `organization`
  is exactly `NetworkManager` (PKI-F-02) - enforced at the nginx
  `location` level via `ssl_verify_client optional` at the server level
  plus an explicit `$ssl_client_verify`/`$ssl_client_s_dn` check per
  request (see `nginx.conf`'s own doc comment for why the check cannot
  live at the listener level: TLS client-certificate verification happens
  during the handshake, before nginx has parsed any HTTP path). Both
  checks fail closed (RD-04): a missing/invalid certificate or the wrong
  organization returns 403 before the request ever reaches Headscale.
- everything else (NM-F-14: `/key`, `/machine/*`, `/ts2021`,
  `/register/{id}`, ... - Headscale's own coordination protocol): open to
  anyone, no client certificate ever requested.

nginx terminates TLS for the one public port with an ORDINARY
publicly-trusted certificate (Let's Encrypt in production, a dev-only
self-signed pair for local Compose testing) - deliberately never RAM-USB's
own internal Certificate-Authority: real end-user Tailscale clients (this
system's own Users, CL-F-04) must be able to trust this certificate too,
and have no reason to trust RAM-USB's private internal CA at all. The
internal CA's root certificate is trusted by nginx for exactly one purpose
- verifying the client certificate offered for `/api/v1/` - never for this
listener's own server identity.

## Container/guest sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 1 vCPU, 512 MB-1 GB RAM: Headscale itself holds every mesh node's
  registration/ACL state in its own SQLite database and serves every
  coordination-protocol connection from every RAM-USB mesh member plus
  every registered end-user client (CL-F-04) - a larger steady-state load
  category than a pure request-relay service (Security-Switch), though
  still modest at this project's dev/thesis scale (a handful of nodes).
- Disk grows with mesh membership: Headscale's SQLite database plus its
  Noise protocol private key (`/var/lib/headscale`, backed by the
  `ramusb-headscale-data` volume in the dev Compose stack) - not
  backup-content data, RNF-SEC-01 is unaffected regardless.

## Network placement (NET-F-01, NM-F-12, NM-F-14)

Like Entry-Hub, Headscale sits outside RNF-ORG-04's Proxmox KVM/LXC split
entirely - a real internet-routable public IP is a hard requirement here,
not a placement choice, since NM-F-14's own justification is that "a newly
registered node has no other way to reach it before completing CL-F-04's
mesh join" (a client that has not yet joined the mesh cannot, by
definition, be reached through the mesh).

One public port, two enforcement regimes, both terminated at this same
VPS:

- nginx's `0.0.0.0:8080` is the ONE deliberately public port in this
  deployment - reachable from the open internet, matching NM-F-14's own
  wording.
- Headscale's own listener (`127.0.0.1:8081`) is loopback-only, reachable
  from nothing but nginx on this same guest - never published, never
  reachable directly even from this project's own private mesh.
- This guest needs NO route into RAM-USB's private mesh/Proxmox cluster
  network at all: every RAM-USB service that calls Headscale's admin API
  (Network-Manager, NM-F-08/09/10/12) does so over the same **public**
  network this coordination endpoint already sits on, presenting its own
  mTLS client certificate - not over the mesh (see
  `deployments/proxmox/network-manager.md`'s own reachability section for
  the full reasoning on that one exception to NET-F-01).

## Dependencies that must exist first

- None from within RAM-USB's own stack - Headscale is deliberately the one
  component every mesh-joined service and Network-Manager's own admin
  client depend ON, not a dependent itself. It needs only:
  - A real, publicly resolvable DNS record for this VPS pointing at its
    Let's Encrypt-issued certificate's hostname, plus an operator-managed
    ACME client (outside this container's own scope) keeping nginx's
    `/etc/headscale-public-tls/cert.pem`/`key.pem` current.
  - RAM-USB's internal Certificate-Authority's root certificate, as a
    plain file (never a bootstrap token - this container has no RAM-USB
    mTLS identity of its own), for nginx's `/api/v1/` client-certificate
    check. `deployments/scripts/headscale.sh` extracts this via
    `docker cp` from the running `certificate-authority` container in the
    dev Compose stack; a production VPS needs an equivalent out-of-band
    copy step, re-run whenever the internal CA's own root rotates.

## Configuration (see `third-party/headscale/config/config.yaml` for the
authoritative dev-only values; a production VPS needs its own copy adapted
to its real public hostname)

| Setting | Purpose |
|---|---|
| `server_url` / coordination base URL | Headscale's own public-facing identity, must match the VPS's real DNS name in production |
| `listen_addr` | `127.0.0.1:8081` - loopback-only, never this VPS's public interface (nginx is the only public surface, see "What this process is" above) |
| `tls_cert_path` / `tls_key_path` | left empty - Headscale runs plain HTTP behind nginx's own TLS termination, its documented "run behind a reverse proxy" mode |
| MagicDNS base domain (NM-F-15) | dedicated base domain so mesh nodes resolve Storage-Service by name rather than IP - configured here, consumed by every mesh-joined service's own MagicDNS resolution |
| ACL policy (NM-F-01/02/03/05/06/07, `policy.mode: database`) | reachability rules, written and maintained by Network-Manager's own `buildACLs` (`services/network-manager/internal/headscale/policy.go`), not edited directly on this VPS |

## What a real (non-dev) deployment still needs, not yet decided here

- A production ACME client (Let's Encrypt) actually managing nginx's
  public-facing certificate on this VPS - only a dev-only self-signed pair
  (`third-party/headscale/dev-tls`) has been exercised so far.
- A production re-copy procedure for RAM-USB's internal CA root whenever
  it rotates (PKI-F-03) - only the dev `docker cp` one-liner
  (`deployments/scripts/headscale.sh`) exists today.
- Backup/durability guarantee for `/var/lib/headscale`'s SQLite database
  at the real VPS level (losing it means every registered mesh node/user
  loses its mesh identity and must re-register) - not yet decided beyond
  the dev Compose stack's own named volume.
- Firewall/hardening for the one genuinely public port on this VPS,
  beyond nginx's own per-path mTLS enforcement documented above - no
  network-level rate-limiting/DDoS mitigation is decided here.
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other component's deployment
  note. Headscale itself is also the one component in this system with no
  SRS-mandated MQTT metrics publish of its own (CA-F-03-style requirement
  does not exist for it) - its health is entirely unobserved by this
  project's monitoring stack today.
