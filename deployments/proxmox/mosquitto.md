# Mosquitto (MQTT-Broker): Proxmox deployment notes

Written directly from `deployments/compose/mqtt-broker.yml`'s own dev-stack
wiring, `third-party/mosquitto/mosquitto.conf`/`acl.conf`'s own doc
comments, `third-party/mosquitto/generate-dev-certs.sh`'s own doc comment,
the SRS's MT-F-01/MT-F-02 table, and `deployments/proxmox/
certificate-authority.md`'s own mesh-reachability reasoning (this document
follows the identical pattern), translated to a Proxmox guest instead of a
Compose service.

**Production reachability rule confirmed directly with the user (same
decision as Certificate-Authority's own doc, not re-derived here)**: in
production, Mosquitto is reachable **only** via the Tailscale mesh - no
host-published port, no plain "internal Docker network" path.

## What this process is

The official `eclipse-mosquitto:2` binary (MT-F-01/MT-F-02: mutual X.509
authentication over TLS 1.3, `require_certificate true` +
`use_identity_as_username true` mapping each client certificate's CN to an
ACL username, default-deny `acl.conf`), plus a Tailscale mesh sidecar -
unchanged in shape from the dev Compose file:

- **A Tailscale mesh sidecar** (`mqtt-broker-mesh` in the dev Compose
  file): Mosquitto is a C binary, so it cannot embed `pkg/mesh` either -
  same sidecar pattern as Certificate-Authority's own doc
  (`network_mode: "service:mqtt-broker"`, `TS_USERSPACE: "false"` for
  inbound reachability - every metrics-publishing service and
  Metrics-Collector must be able to *reach* this broker, not just the
  broker reaching out). No SRS ID names MQTT-Broker's own mesh
  reachability the explicit way NM-F-04 names it for Certificate-Authority
  (flagged in `deployments/compose/mqtt-broker.yml`'s own top comment,
  still unresolved as of this writing) - this document treats
  mesh-only reachability as required anyway, per RNF-SEC-04/NET-F-01 and
  the user's own explicit instruction this session, independent of that
  open naming gap.

## No published ports - hard requirement, not a "should"

Same rule as Certificate-Authority's own doc: unlike the current dev/test
Compose stack (`deployments/compose/mqtt-broker.yml`, which still publishes
`8883:8883` and keeps `networks: ramusb-net` on the main container -
deliberate, dev-only, tracked by KI-05), the production guest's
`mqtt-broker` container publishes **no port at all** to the guest's real
network interface. The only way to reach it - for every metrics-publishing
RAM-USB service and Metrics-Collector alike - is the mesh sidecar's
Tailscale IP/MagicDNS hostname. RNF-SEC-04 (mTLS on every inter-service
call) and NET-F-01 (inter-service communication over the private network
only) both already require this; the sidecar's own outbound connectivity
to Headscale (below) still flows through the guest's normal Docker
bridge/NAT and its real route to the internet.

## The mesh sidecar's control-plane URL points at Headscale's real public VPS address

Identical reasoning to Certificate-Authority's own doc (see that file for
the full explanation and the KI-05 cross-reference): in production,
Headscale is not a container sharing this guest's Docker daemon - it runs
on its own separate, publicly-addressable VPS (NM-F-14). `mqtt-broker-mesh`'s
`TS_EXTRA_ARGS`'s `--login-server` (and `RAM_USB_TAILSCALE_CONTROL_URL`
generally) must point at Headscale's real public hostname, reached over
this guest's normal internet route - never the dev stack's Docker DNS
shortcut (`https://headscale:8080`), since nothing else shares this
guest's Docker daemon in production.

Unlike Certificate-Authority, Mosquitto has no `pkg/pki`/`ca.BootstrapServer`
dialer-routing concern of its own to resolve (it is not a Go process and
does not call that library at all) - every consumer publishing metrics to
it already routes through its own real `tailscaled` kernel interface (see
Certificate-Authority's doc for why that resolves mesh-only reachability
for every server-role RAM-USB consumer in production).

## LXC vs KVM placement (RNF-ORG-04)

RNF-ORG-04 places Mosquitto on an **LXC** container ("the other services,"
alongside Security-Switch and Certificate-Authority - not the KVM group
reserved for Storage-Service/Database-Vault/Network-Manager). Same
reasoning as Certificate-Authority's own doc: this guest needs nothing
beyond what the Tailscale sidecar itself requires
(`NET_ADMIN`/`NET_RAW`/`/dev/net/tun`, `TS_USERSPACE=false`) - Mosquitto
itself does no POSIX-user provisioning, `chroot`, or raw-socket work.
Same unprivileged-LXC `/dev/net/tun` enablement caveat as
Security-Switch's/Certificate-Authority's own docs (not yet verified
against a real Proxmox LXC guest).

## Dependencies that must exist first

- Certificate-Authority, reachable over the mesh (see that document), for
  Mosquitto's own broker-side TLS identity issuance AND ongoing renewal
  (KI-16, PKI-F-03) - see "Mosquitto's own TLS certificate provisioning
  and renewal" below for the full design, both now resolved for
  production.
- The separately-deployed Headscale/reverse-proxy VPS (NM-F-14), reachable
  at `RAM_USB_TAILSCALE_CONTROL_URL` over the public internet, to mint this
  guest's own single-use Tailscale pre-auth key
  (`RAM_USB_MQTT_BROKER_TAILSCALE_AUTHKEY`, tagged `tag:mqtt-broker`)
  before the mesh sidecar can join.

## Environment variables (see `deployments/compose/mqtt-broker.yml` for the dev-stack values this table generalizes)

Mosquitto itself takes no `RAM_USB_*` environment variables - all of its
configuration is file-based (`mosquitto.conf`, `acl.conf`, certificate
files under `/mosquitto/certs`). The mesh sidecar takes the same two
variables as every other sidecar in this project:

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | Headscale's real public VPS coordination URL - never a Docker DNS shortcut in production, see above |
| `RAM_USB_MQTT_BROKER_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:mqtt-broker`, minted on the Headscale VPS |

Every required variable above is a hard startup failure if unset (RD-04,
fail-secure).

## Mosquitto's own TLS certificate provisioning and renewal (KI-16, PKI-F-03, RESOLVED 2026-07-25)

Every RAM-USB Go service's mTLS identity comes from CA-F-04's bootstrap-token
flow, consumed live by a running process (`pkg/pki.NewServer`/`NewClient`).
Mosquitto cannot use that flow at all - it is a C binary with no `pkg/pki`
integration, and CA-F-04's bootstrap token is explicitly single-use,
consumed by a live process at its own startup, not reusable for minting a
static file pair from an external script. This is now solved the same way
for both dev and production, via two new Compose services in
`deployments/compose/mqtt-broker.yml` (design cross-verified this session
against Smallstep's and Mosquitto's own official documentation, then
proven end-to-end against a real running Certificate-Authority and a real
Headscale mesh):

- **`mqtt-broker-cert-issuer`** (one-shot, `smallstep/step-cli`): the
  initial-issuance half of CA-F-04's bootstrap-token flow, `step ca
  certificate <subject> ... --token ...`, run as a genuine NETWORK call
  (not `docker exec`) so it works whether or not Mosquitto and
  Certificate-Authority share a Docker host - the same cross-host-capable
  design `third-party/mosquitto/generate-dev-certs.sh`'s own certificate-
  exchange step already established, now wired as a proper Compose
  one-shot instead of a script an operator runs by hand. Mints BOTH
  identities Mosquitto's own container needs: its server certificate
  (`MQTTBroker`) and the healthcheck's own client identity
  (`CertificateAuthority`, reusing that string per `acl.conf`'s own
  pre-existing grant). Token MINTING itself stays a manual, out-of-band,
  `docker exec`-based operator step (`deployments/scripts/mqtt-broker.sh`
  in dev; the production equivalent is whatever CA-admin access an
  operator already has) - the same "docker exec is legitimately an
  admin/CA-operator action" reasoning `generate-dev-certs.sh`'s own doc
  comment already established, unchanged here.
- **`mqtt-broker-cert-renewer`** (long-running, `smallstep/step-cli`):
  `step ca renew --daemon`, one process per identity, authenticated purely
  by the certificate being renewed (mTLS) - no token needed after the
  first issuance, confirmed live this session (a manual `step ca renew`
  against the real CA succeeded with no `--token` at all, producing a
  genuinely new certificate). Renews before ~2/3 of the ~24h leaf lifetime
  elapses by default (Smallstep's own documented default, not a value
  this project configures). `--exec "kill -HUP 1"` reloads Mosquitto's
  `certfile`/`keyfile` in place, without dropping already-established
  connections - both the renewal itself and mosquitto.conf(5)'s documented
  SIGHUP behavior were confirmed live this session, not merely read from
  the man page.
- **PID namespace sharing** (`pid: "service:mqtt-broker"`) is how the
  renewer's `--exec "kill -HUP 1"` reaches the real mosquitto process:
  confirmed live that mosquitto is PID 1 inside any container joining its
  namespace (the official `eclipse-mosquitto` image's own entrypoint ends
  `exec "$@"`, so mosquitto itself, not a wrapper shell, holds that PID).
- **Network namespace sharing** (`network_mode: "service:mqtt-broker"`,
  same directive `mqtt-broker-mesh` itself already uses, confirmed live
  this session that Compose accepts BOTH `pid:` and `network_mode:`
  pointing at the same target simultaneously) is what lets the renewer's
  own outbound calls to Certificate-Authority cross the Tailscale mesh in
  production, where Certificate-Authority has no other reachable path (see
  this document's own "no published ports" section above) - the renewer
  inherits whatever mesh interface `mqtt-broker-mesh` has already
  established in that shared namespace, with no capabilities/tun device of
  its own needed.
- **A real Headscale ACL gap was found and fixed as part of this work**:
  `services/network-manager/internal/headscale/policy.go`'s existing
  Certificate-Authority reachability rule only listed the five original
  Go-service tags as valid sources - `tag:mqtt-broker` (the mesh identity
  `mqtt-broker-mesh`/`mqtt-broker-cert-renewer` share) was never included,
  since nothing previously needed the MQTT broker's own mesh identity to
  ever initiate an OUTBOUND connection (every existing rule only lets
  other services connect INTO it). Confirmed live: without this fix, a
  renewal attempt over the mesh hangs until "context deadline exceeded"
  with no other error (the standard silent-deny-at-the-receiving-node
  behavior this project's own operational notes already document for a
  missing ACL rule) - fixed by adding `TagMQTTBroker` to that rule's `Src`
  list, re-verified live (a direct TLS dial to Certificate-Authority's
  real mesh IP, with the correct SNI, now succeeds end-to-end).
- **Confirmed but not independently provable in THIS dev stack**: because
  the dev Compose file keeps `mqtt-broker` dual-reachable (KI-05,
  deliberately unfixed there), Docker's own embedded DNS resolver wins
  over the mesh sidecar's DNS inside the shared namespace, so the actual
  running renewer's `https://certificate-authority:9000` calls resolve to
  the `ramusb-net` IP in dev, not the mesh IP - even though the mesh path
  itself was independently proven functional (see above) and is the ONLY
  path that will exist once KI-05's production topology applies (no
  `ramusb-net` on that guest at all). This is the same dev/production gap
  KI-05 already documents for every other Certificate-Authority consumer,
  not a new limitation introduced by this fix - see
  `MANUAL-DISTRIBUTED-RUN.md`'s own Known Issues list for the exact live
  evidence.

## What a real (non-dev) deployment still needs, not yet decided here

- **`acl.conf`'s own distribution/update mechanism**: the dev stack
  bind-mounts a static file from the repo - a production guest needs a
  real deployment/config-management story for keeping it current as new
  services are added (each new metrics-publishing service needs its own
  ACL entry).
- **Persistence**: the dev config sets `persistence false` - a production
  deployment should confirm whether that is still the right choice (no
  retained-message/durable-subscription state is currently expected of
  this broker, but this has not been explicitly re-confirmed for
  production).
- Log shipping/monitoring of this process's own health beyond
  `log_dest stdout`, same open item as every other component's Proxmox
  note.

## Container sizing (dev/thesis-scale judgment call, not a measured production figure)

- 1 vCPU, 256-512 MB RAM: Mosquitto's own steady-state load here is
  bursty and light - one publish per minute per RAM-USB service (EH-F-10,
  SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03) plus Metrics-Collector's
  subscriptions, not a continuous high-throughput data path.
- Minimal disk: `persistence false` means no retained-message store to
  size for; only the broker's own certificate/key files and static config.
