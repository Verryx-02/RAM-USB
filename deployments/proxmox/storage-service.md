# Storage-Service: Proxmox deployment notes

Written directly from `services/storage-service/cmd/storage-service/main.go`'s
own package doc comment and `const` block,
`services/storage-service/cmd/authorized-keys-command/main.go`'s and
`services/storage-service/cmd/identity-provisioner/main.go`'s own doc
comments, `deployments/docker/storage-service/Dockerfile`'s doc comment,
`deployments/docker/storage-service/sshd_config`, and
`deployments/compose/storage-service.yml`'s dev-stack wiring, translated to
a Proxmox guest instead of a Compose service - same approach
`metrics-collector.md` used, since (as of this writing) no other
`deployments/proxmox/*.md` file exists yet to mirror instead.

## What this process is

Storage-Service is the one component genuinely doing OS-level work, per
the SRS 4.5 `[!NOTE]` right after its directory-structure diagram: four
independent long-lived processes, s6-overlay-supervised on a
`debian:bookworm-slim` base (`deployments/docker/storage-service/rootfs/
etc/s6-overlay/s6-rc.d/`, one `longrun` directory each) -

- `tailscaled`, a real OS-level mesh client;
- a hardened `sshd` (ST-F-03/04/07/08/09: SFTP-only, no password
  authentication, no root login, `ChrootDirectory` per user);
- this repo's own storage-service Go mTLS HTTP server (ST-F-01/06/10),
  which creates a POSIX user (`useradd`/`groupadd`, `user<xxxxxx>`,
  ST-F-06) on every request from Database-Vault and reports the outcome
  back in that same HTTP response (ST-F-10 - there is no separate outbound
  call anywhere in this service);
- `identity-provisioner`, which keeps `authorized-keys-command`'s own mTLS
  identity and config file on disk current (ST-F-11, see below).

A fifth binary, `authorized-keys-command`, is installed alongside but is
**not** s6-overlay-supervised: `sshd`'s own `AuthorizedKeysCommand`
directive invokes it once per SFTP connection attempt, running as a
dedicated unprivileged system account (`sshd-authkeys`) with no other role
on the host. It looks up the connecting user's current SSH public key from
Database-Vault over mTLS (ST-F-11) and denies the connection fail-secure
(RD-04) on any lookup failure.

The container runs with `cap_drop: ALL` plus a minimal added set
(`CHOWN`, `SETUID`, `SETGID`, `SYS_CHROOT` for user creation and sshd's
own per-connection setuid/chroot; `NET_ADMIN`, `NET_RAW` and
`/dev/net/tun` for `tailscaled`'s kernel TUN interface), per RNF-SEC-03/
RNF-REL-01. `tailscaled` is a real OS-level client here because `sshd` - a
C binary, outside the reach of any application-level dial injection -
needs a genuine kernel network interface to bind and accept connections on
at all.

## Container sizing (dev/thesis-scale judgment call, not a measured
production figure)

- 2 vCPU, 1-2 GB RAM: `sshd`'s own per-connection forking plus concurrent
  SFTP transfers are the actual CPU/RAM driver here, not the Go binary
  itself (which does no per-file I/O of its own - all backup upload/
  download traffic is `sshd`'s SFTP subsystem talking directly to each
  user's chroot).
- **Disk is the dominant sizing factor for this service specifically,
  unlike every other Proxmox note in this group**: `/storage/`'s
  `user<xxxxxx>/data/` subdirectories hold every user's actual
  client-side-encrypted backup content (ST-F-02, RNF-SEC-01 - this
  process itself never sees plaintext). Total disk must scale with
  expected aggregate backup volume across all registered users, not with
  request rate or connection count - revisit this figure directly against
  real usage once the system has real users, since no per-user quota
  exists yet (ST-F-14 is a "should," not yet built).

## Network placement (NET-F-01, RNF-ORG-04)

RNF-ORG-04 places Storage-Service on a **KVM** guest (grouped with
Database-Vault and Network-Manager). A full VM avoids a second layer of
UID-namespace mapping that running per-tenant POSIX users, `setuid`, and
`chroot` inside an already-namespaced LXC guest would add on top of this
container's own already-careful capability scoping - consistent with why
the other two KVM-placed services also need a real kernel network stack
for `tailscaled` (see `deployments/proxmox/database-vault.md`'s own
placement reasoning).

Both `sshd` and the Go mTLS listener bind exclusively to this node's real
Tailscale mesh interface address once `tailscaled` joins - never
`0.0.0.0` or a private-network-only address (NET-F-01, fixed since an
earlier version of this container also published `sshd`'s port on the
Docker host). Reachable only by NM-F-01/NM-F-05's allow-list (Database-
Vault's mTLS calls; only authenticated Users' mesh nodes, tagged per
SS-F-05's 12-hour grant, for SFTP) - enforced at the mesh ACL layer by
Network-Manager's `buildACLs`, not by anything in this container itself.

## Dependencies that must exist first

- Certificate-Authority, reachable to mint this container's two single-use
  bootstrap tokens (CA-F-04): `RAM_USB_CA_BOOTSTRAP_TOKEN` for the Go mTLS
  listener's identity, and `RAM_USB_STORAGE_SERVICE_AKC_BOOTSTRAP_TOKEN`
  for `identity-provisioner`'s.
- The separately-deployed Headscale/reverse-proxy container
  (`deployments/compose/headscale.yml`), reachable at
  `RAM_USB_TAILSCALE_CONTROL_URL` to mint this node's single-use Tailscale
  pre-auth key (`RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY`, tagged
  `tag:storage-service`) before this container's own `tailscaled` can
  join the mesh.
- Database-Vault, reachable both as this listener's own allowed caller
  (ST-F-01) and as `authorized-keys-command`'s own outbound lookup target
  (ST-F-11, Database-Vault's public-key listener,
  `RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR`).
- The MQTT broker (Mosquitto), reachable at `RAM_USB_MQTT_BROKER_URL`,
  with this service's ACL grant already in place (ST-F-12).

## Environment variables (see `main.go`'s own `const` block for the
authoritative list and each one's doc comment)

| Variable | Required | Purpose |
|---|---|---|
| `RAM_USB_STORAGE_SERVICE_LISTEN_ADDR` | yes | Real host:port this server listens on for Database-Vault's inbound mTLS connections (ST-F-01, ST-F-06); assembled at container start from this node's real Tailscale IPv4 plus a port (the dev Compose file sets only the port half, `RAM_USB_STORAGE_SERVICE_LISTEN_PORT: "8448"`) |
| `RAM_USB_MQTT_BROKER_URL` | yes | MQTT broker address, e.g. `tls://mqtt-broker:8883` (ST-F-12) |
| `RAM_USB_CA_BOOTSTRAP_TOKEN` | yes | Single-use CA bootstrap token (CA-F-04) for this process's own inbound-only identity |
| `RAM_USB_STORAGE_SERVICE_MESH_HOSTNAME` | yes | This node's MagicDNS short name within the Headscale mesh (also the name `authorized-keys-command`'s AuthorizedKeysCommand consumers/other mesh nodes resolve this node by, NM-F-15) |
| `RAM_USB_TAILSCALE_CONTROL_URL` | yes | The Headscale coordination URL - the separately-deployed `headscale` container/VPS |
| `RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY` | yes | Single-use Tailscale pre-auth key, tagged `tag:storage-service` |
| `RAM_USB_STORAGE_SERVICE_AKC_BOOTSTRAP_TOKEN` | yes | `identity-provisioner`'s OWN single-use CA bootstrap token (CA-F-04, organization `StorageService`), distinct from `RAM_USB_CA_BOOTSTRAP_TOKEN` because a bootstrap token is single-use and two processes in this container each need one |
| `RAM_USB_DATABASE_VAULT_PUBLIC_KEY_URL` | yes | Database-Vault's ST-F-11 public-key lookup base URL, e.g. `https://database-vault:8446`; `identity-provisioner` writes it verbatim into `authorized-keys-command.conf`'s `database_vault_url` key |

`authorized-keys-command` does **not** read environment variables at all
(sshd invokes it with a minimal, sanitized environment by design) - it
reads its own mTLS client identity and Database-Vault's base URL from a
fixed config file, `/var/lib/storage-service-identity/authorized-keys-command.conf`
(`services/storage-service/cmd/authorized-keys-command/main.go`'s
`configPath` constant). That file, plus the certificate/key/CA-bundle it
points at (`akc-client.crt`, `akc-client.key`, `akc-ca.crt` in the same
directory), is written by the `identity-provisioner` longrun
(`services/storage-service/cmd/identity-provisioner/main.go`): it
bootstraps its own mTLS identity from the Certificate-Authority with the
token above, writes the config once, and re-encodes the current
certificate/key to disk every five minutes so the on-disk copy tracks
`pkg/pki`'s automatic renewal. `sshd` starts only after that first write
lands (`s6-rc.d/sshd/dependencies.d/identity-provisioner-ready`). Every
required variable in the table above is a hard startup failure if unset
(RD-04, fail-secure).

## What a real (non-dev) deployment still needs, not yet decided here

- ST-F-14 (per-user quota limits) and ST-F-15 (replication/fault
  tolerance via CephFS) are both explicitly "should"/nice-to-have, not
  built - directly relevant to this note's own disk-sizing section above.
- The real Proxmox KVM guest's own disk-provisioning strategy for
  `/storage/` at production scale (see "Container sizing" above) - not
  yet decided.
- Log shipping/monitoring of this process's own health beyond `slog`'s
  stdout output, same open item as every other service's Proxmox note.
