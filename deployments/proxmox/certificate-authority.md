# Certificate-Authority: Proxmox deployment notes

Written directly from `deployments/compose/certificate-authority.yml`'s own
dev-stack wiring (`third-party/certificate-authority/enable-json-logger.sh`,
`init-organization-template.sh`), the SRS's CA-F-01..04 table, and
`deployments/proxmox/network-manager.md`'s/`deployments/vps/headscale.md`'s
own precedent for reaching Headscale in production, translated to a
Proxmox guest instead of a Compose service - same approach
`security-switch.md`/`storage-service.md`/`network-manager.md` used.

**Production reachability rule confirmed directly with the user (not
re-derivable from KI-05's own text, which documents a dev-Compose-only
problem)**: in production, Certificate-Authority is reachable **only**
via the Tailscale mesh - no host-published port, no plain "internal
Docker network" path, nothing. See "Network placement" below for why this
does not hit the same chicken-and-egg problem KI-05 describes for the
single-host dev stack.

## What this process is

The official `smallstep/step-ca` binary (CA-F-01/CA-F-02, "provided by
the underlying product" per the SRS's own note), plus two things RAM-USB
adds around it, unchanged in shape from the dev Compose file:

- **`certificate-authority-init`**: a one-shot step that applies
  `organization.x509.tpl` to the "admin" provisioner (PKI-F-02) so every
  certificate this CA issues carries the requesting subject in both
  CommonName and `Subject.Organization` - runs once, after the CA reports
  healthy, then exits.
- **A Tailscale mesh sidecar** (`certificate-authority-mesh` in the dev
  Compose file): step-ca is a third-party C/Go binary that does not embed
  `pkg/mesh`, so mesh membership comes from a real `tailscale/tailscale`
  sidecar container sharing this process's own network namespace
  (`network_mode: "service:certificate-authority"`), with
  `TS_USERSPACE: "false"` - required for the CA to *accept* inbound mesh
  connections (NM-F-04: "all internal components... can contact, and be
  contacted by, the Certificate-Authority over the mesh network"), not
  just originate them. `TS_USERSPACE`'s default (userspace-networking, a
  netstack invisible to the shared namespace's other process) silently
  rejects every inbound TCP SYN - see
  `.claude/agent-memory/code-agent.md`'s "Sidecar mesh pattern" entry for
  the live-confirmed mechanics.
- **CA-F-03's metrics sidecar**: since `docs/Known_Issues.md`'s KI-28, this
  is no longer a separate container/Compose project at all - it is a
  second process, s6-supervised alongside step-ca itself, INSIDE this same
  `certificate-authority` container/image
  (`deployments/docker/certificate-authority/`). It tails step-ca's own
  JSON access log (`services/certificate-authority/cmd/metrics-sidecar/`)
  from a plain local filesystem path (no shared Docker volume needed
  anymore - both the writer, step-ca, and the reader are processes inside
  ONE container now) and republishes RequestCount/ErrorCount/
  AverageResponseTimeMs via `pkg/metrics`, like every other RAM-USB
  service's own CA-F-03/MT-F-01-class metrics publish. Co-location on
  this guest was already a hard technical requirement before KI-28
  (confirmed directly by the user, resolving `docs/Known_Issues.md`'s
  KI-11 for this component) - KI-28 went one step further and merged the
  two PROCESSES into one container, not just one guest, because that same
  co-location also gives this process a real route to a mesh-only
  Certificate-Authority in production (see "Why this is a single
  container, not two" below). It keeps its own separate CA-F-04 bootstrap
  token (subject `CertificateAuthority` - the SRS service identity
  Mosquitto's ACL actually authorizes, not this container's own name),
  minted LOCALLY once step-ca itself is healthy (`step ca token
  CertificateAuthority --ca-url https://localhost:9000 ...`, no `docker
  exec`/cross-container call needed - see
  `deployments/docker/certificate-authority/rootfs`'s own
  mint-metrics-token oneshot) - but no separate Tailscale mesh identity of
  its own anymore: it rides the SAME real `tailscaled` sidecar
  (`certificate-authority-mesh`) step-ca's own inbound mesh reachability
  already depends on, since both processes now share that sidecar's
  network namespace.

## Why this is a single container, not two (KI-28)

Before KI-28, the metrics sidecar was a separate container using `pkg/mesh`
(in-process `tsnet`) for its own MQTT publish and its own separate CA-F-04
bootstrap-token exchange. Live verification (mirroring KI-27's own method
for Entry-Hub, see `docs/Known_Issues.md`) found this had the identical
gap: `pkg/pki`'s CA-bootstrap-token exchange has no interceptable dial
path (a hard `github.com/smallstep/certificates` library limitation, see
`.claude/agent-memory/code-agent/pkg-pki-dialer-routing.md`), so it always
goes out over the container's ordinary default route, never through
`pkg/mesh`'s own `Dial`. In production, per this document's own "No
published ports" rule above, Certificate-Authority's ordinary default
route from any OTHER container is unreachable - only its mesh sidecar's
Tailscale IP/MagicDNS hostname works, and `pkg/mesh` has no OS-level route
onto that mesh at all. Merging the metrics sidecar into Certificate-
Authority's own container removes this at its root instead of routing
around it: the CA-bootstrap-token exchange becomes a purely local call
(`https://localhost:9000`, no network hop, no mesh dependency of any
kind), and the only remaining outbound call this process makes - its
MQTT publish - rides the real kernel `tailscale0` interface the mesh
sidecar already provides for step-ca's own inbound reachability, since
both processes now share that sidecar's network namespace. No separate
Tailscale pre-auth key, no separate `pkg/mesh` mesh-join code, is needed
for this process anymore.

## No published ports - hard requirement, not a "should"

Unlike the current dev/test Compose stack (`deployments/compose/
certificate-authority.yml`, which still publishes `9000:9000` and keeps
`networks: ramusb-net` on the main container - a deliberate, dev-only
simplification, see KI-05), the production guest's `certificate-authority`
container publishes **no port at all** to the guest's real network
interface, and joins no plain container network shared with anything else
(there is nothing else to share with - RNF-ORG-04 gives this service its
own dedicated VM/LXC guest). The only way to reach it is the mesh sidecar's
Tailscale IP/MagicDNS hostname. This follows directly from RNF-SEC-04
(mTLS on every inter-service call) and NET-F-01 (inter-service
communication over the private network only) - the user's own explicit
instruction this session, not a new inference from those requirements
alone. The mesh sidecar's own outbound connectivity to Headscale (below)
still flows through the guest's normal Docker bridge/NAT and the guest's
real `eth0` route to the internet - only *inbound* reachability to this
container is mesh-restricted.

## The mesh sidecar's control-plane URL points at Headscale's real public VPS address

Same pattern Network-Manager's own Proxmox doc already documents for its
own mesh join (`deployments/proxmox/network-manager.md`'s "Dependencies
that must exist first" section) and Headscale's own VPS doc confirms from
the other side (`deployments/vps/headscale.md`): in production, Headscale
is not a container sharing this guest's Docker daemon - it runs on its own
separate, publicly-addressable VPS (NM-F-14), reachable only over the
guest's normal internet route. So `certificate-authority-mesh`'s
`TS_EXTRA_ARGS`'s `--login-server` (and `RAM_USB_TAILSCALE_CONTROL_URL`
generally) must be set to Headscale's real public hostname (e.g.
`https://headscale.example.org:8080`), never a Docker DNS shortcut like
the dev stack's `https://headscale:8080` - there is no `headscale`
hostname to resolve on this guest's own Docker network in production,
since nothing else shares it. This is the same reasoning that resolves
KI-05's "chicken-and-egg" problem: KI-05's blocker (the sidecar needs
*some* network path to Headscale, but Headscale can never itself be a
mesh member) only exists because the dev stack co-locates Headscale as
just another `ramusb-net` container. In production there is no
`ramusb-net` to depend on in the first place - the sidecar reaches
Headscale exactly the way every other mesh-joining service already does,
over the public internet, authenticated by mTLS/its own bootstrap
material, never by a shared Docker network.

**Also resolves the "hard library limitation" flagged in
`.claude/agent-memory/code-agent.md`'s "pkg/pki dialer routing" entry**:
that entry notes `ca.BootstrapServer`'s certificate-renewal traffic has no
interceptable dial path, so a server-role consumer of this CA "needs
`ramusb-net` reachability to it for the lifetime of the process." That
constraint is specific to the dev stack's Docker-network-based reachability
model. Every production consumer holding a server role (Security-Switch,
Database-Vault, Storage-Service, Network-Manager) already runs a real
OS-level `tailscaled`, not `pkg/mesh`'s in-process `tsnet` - a genuine
kernel `tailscale0` interface routes *every* outbound connection that
process makes, including step-ca SDK-internal renewal calls, transparently
through the mesh with zero application-level dial interception needed (see
`deployments/proxmox/security-switch.md`'s own "What this process is"
section). So a consumer resolving this CA's MagicDNS hostname reaches it
over the mesh automatically - mesh-only reachability for the CA does not
reintroduce the dialer-routing limitation in production, only in a
hypothetical `pkg/mesh`-based consumer (Entry-Hub, client-role only, is
unaffected either way).

## LXC vs KVM placement (RNF-ORG-04)

RNF-ORG-04 places Certificate-Authority on an **LXC** container ("the
other services," alongside Security-Switch - not the KVM group reserved
for Storage-Service/Database-Vault/Network-Manager). Same reasoning class
as `deployments/proxmox/security-switch.md`'s own placement note: this
guest needs nothing beyond what the Tailscale sidecar itself requires
(`NET_ADMIN`/`NET_RAW`/`/dev/net/tun` for the sidecar's real kernel
`tailscale0` interface, `TS_USERSPACE=false`) - step-ca itself does no
POSIX-user provisioning, `chroot`, or raw-socket work of its own, unlike
Storage-Service's real reason for needing a full KVM guest (avoiding a
second UID-namespace layer on top of `useradd`/`setuid`/`chroot`). An
**unprivileged** Proxmox LXC guest needs the same explicit `/dev/net/tun`
enablement Security-Switch's own doc describes
(`lxc.cgroup2.devices.allow: c 10:200 rwm` plus a `/dev/net/tun` mount, or
running this stack's Docker image with `nesting`/`keyctl` features) - not
yet verified against a real Proxmox LXC guest, same open item as
Security-Switch's.

## Dependencies that must exist first

- The separately-deployed Headscale/reverse-proxy VPS (NM-F-14), reachable
  at `RAM_USB_TAILSCALE_CONTROL_URL` over the public internet, to mint this
  guest's own single-use Tailscale pre-auth key
  (`RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY`, tagged
  `tag:certificate-authority` per Network-Manager's own ACL policy,
  `services/network-manager/internal/headscale/policy.go`) before the mesh
  sidecar can join at all - this is a genuine bootstrap dependency (the CA
  itself has nothing to bootstrap FROM in the mesh-join direction; unlike
  every other RAM-USB service, the CA does not consume a CA-F-04 bootstrap
  token for its own inbound mTLS identity - `smallstep/step-ca` mints and
  holds its own root, DOCKER_STEPCA_INIT_* only).
- The metrics sidecar's own CA-F-04 bootstrap token is minted internally,
  by this container's own `mint-metrics-token` oneshot, once step-ca
  itself reports healthy - no external dependency, no `docker exec`, no
  separate pre-auth key (KI-28).
- The MQTT broker (Mosquitto), reachable over the mesh, with the metrics
  sidecar's own ACL grant (`user CertificateAuthority` / `topic write
  metrics/Certificate-Authority`) already in place, before its periodic
  publish loop can succeed - this container's own `mqtt-broker-ready`
  oneshot gates the metrics sidecar's own start on this.
- Nothing else beyond the above - Certificate-Authority is, by design, the
  one component every other RAM-USB service depends ON for its own initial
  identity (CA-F-04), not a dependent of any RAM-USB service itself, aside
  from the Headscale mesh-join dependency and the metrics sidecar's own
  MQTT-broker dependency above.

## Environment variables (see `deployments/compose/certificate-authority.yml` for the dev-stack values this table generalizes)

| Variable | Required | Purpose |
|---|---|---|
| `DOCKER_STEPCA_INIT_NAME` | yes | The CA's own display name, set once at first boot (persisted in the CA's own data volume thereafter) |
| `DOCKER_STEPCA_INIT_DNS_NAMES` | yes | Every hostname/IP this CA's own server certificate must carry as a SAN - in production, this guest's real mesh hostname (and `localhost`), not the dev stack's Docker-DNS-friendly `certificate-authority` |
| `DOCKER_STEPCA_INIT_PASSWORD_FILE` | yes | Path to the CA's own admin/provisioner password file - the same secret `certificate-authority-init`'s organization-template application and every dev-only `docker exec ... step ca token` mint already require; needs its own real secrets-management story in production, not a bind-mounted plaintext file (see "What a real deployment still needs" below) |
| `DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT` | yes | Enables the admin API `certificate-authority-init`'s provisioner-template step needs |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | Headscale's real public VPS coordination URL - **never** a Docker DNS shortcut in production, see above |
| `RAM_USB_CERTIFICATE_AUTHORITY_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:certificate-authority`, minted on the Headscale VPS |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure) - `TS_AUTHKEY`'s own `${VAR:?message}` form in the dev
Compose file is the pattern a production secrets-injection mechanism
should preserve.

### The metrics sidecar's own environment variables (see `deployments/compose/certificate-authority.yml`)

Since KI-28, these are part of the SAME container's own env block, not a
separate process's - the metrics sidecar reads them via s6-overlay's
`with-contenv`, same as every other environment-variable-driven RAM-USB
process.

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_CERTIFICATE_AUTHORITY_ACCESS_LOG_PATH` | yes | Path to the local JSON access log this process tails - `/var/log/certificate-authority/access.log`, written by step-ca's own tee'd command in the SAME container/filesystem, no shared volume needed |
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, reached over the mesh via the shared `certificate-authority-mesh` sidecar, e.g. `tls://mqtt-broker:8883` |

`RAM_USB_CA_BOOTSTRAP_TOKEN` is no longer a Compose-level/operator-provided
variable for this process - it is minted internally by the container's own
`mint-metrics-token` oneshot and handed to the metrics sidecar longrun via
s6-overlay's own container-environment directory (KI-28). Every required
variable above is a hard startup failure if unset (RD-04, fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- **`DOCKER_STEPCA_INIT_PASSWORD_FILE`'s real secret**: the dev stack
  bind-mounts a plaintext file
  (`third-party/certificate-authority/config/password.dev-only.txt`) -
  production needs a real secrets-management mechanism for this (and for
  the CA's own root/intermediate private keys, `/home/step`'s persisted
  volume), not yet decided.
- **A production DNS/SAN naming decision for `DOCKER_STEPCA_INIT_DNS_NAMES`**:
  the dev stack's `localhost,certificate-authority` assumes a
  Docker-DNS-resolvable hostname that won't exist in production - needs
  this guest's real MagicDNS short name (and whatever else consumers
  resolve it by) decided and pinned before first boot, since step-ca's own
  root/leaf SANs are fixed at CA initialization time.
- **`certificate-authority-init`'s own re-run/verification story**: the
  dev stack runs this as a one-shot Compose service gated on
  `service_healthy`, OUTSIDE the certificate-authority container itself
  (unlike the metrics sidecar, KI-28 did not fold this step in, since it
  targets the CA's own HTTPS API rather than needing anything from inside
  this container) - a production guest needs an equivalent one-shot step
  wired into whatever supervises this guest's own startup, or a plain
  systemd oneshot on the LXC guest itself.
- **`/home/step`'s durability guarantee** at the real Proxmox guest level
  (a persistent disk/volume surviving guest restart, not just container
  restart) - same open item as every other service's Proxmox note, but
  higher-stakes here: losing this volume means every other RAM-USB
  service's trust anchor is gone.
- Log shipping/monitoring of this process's own health beyond
  `docker logs`/its own JSON access log, same open item as every other
  service's Proxmox note.

## Container sizing (dev/thesis-scale judgment call, not a measured production figure)

- 1 vCPU, 256-512 MB RAM: step-ca's own steady-state load is bursty and
  light (short-lived-certificate issuance/renewal requests, not a
  continuous data path) - the same request-relay-adjacent category as
  Security-Switch's own sizing note, plus the mesh sidecar's modest
  footprint. The metrics sidecar's own footprint is smaller still (a
  single Go binary, co-supervised in the same container, tailing one log
  file and publishing once a minute) - no separate sizing line item needed
  on top of this guest's existing headroom.
- Minimal disk: the CA's own root/intermediate key material and its
  provisioner/config state (`/home/step`) - grows with issued-certificate
  history, not with any user-facing content. The access-log volume
  (`ramusb-certificate-authority-logs`, now used only within this one
  container, KI-28) grows with request volume - not currently rotated/
  truncated, an open item shared with "What a real deployment still needs"
  above.
