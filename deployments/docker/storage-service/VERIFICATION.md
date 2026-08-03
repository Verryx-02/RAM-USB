# Storage-Service container verification

This is the manual system-test procedure for ST-F-02 through ST-F-11's OS-level guarantees: chroot isolation, SFTP-only access, sshd hardening, and public-key resolution via `AuthorizedKeysCommand`. It exercises Storage-Service's real container against a real Database-Vault, per `Test_Plan.md` §2.3's system-test technique (full stack, real mTLS certificates).

## Mesh architecture (NET-F-01)

Storage-Service's container runs `sshd` - a C binary that needs a genuine kernel network interface. This container therefore runs a real, OS-level `tailscaled` client, supervised by s6-overlay alongside `sshd`, the `storage-service` Go binary and `identity-provisioner` (see the SRS 4.5 `[!NOTE]`). `tailscaled` joins the mesh once at container start (`tailscale-up` oneshot, `rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/`) and stays up for the container's whole lifetime; `sshd` and `storage-service` both wait on that oneshot (s6-rc dependency) before starting, since both bind exclusively to the discovered Tailscale interface address, never `0.0.0.0`/`ramusb-net`/a host-published port.

## Prerequisites

- Docker.
- A running Database-Vault: `./deployments/scripts/database-vault.sh` (one container bundling its own Postgres, `deployments/compose/database-vault.yml` - the script generates and consumes that Postgres password itself). Its schema is applied automatically: `cmd/database-vault/main.go` runs `internal/schema`'s migrations at startup, before it serves anything.
- A real Headscale instance (`deployments/compose/headscale.yml`) reachable at `RAM_USB_TAILSCALE_CONTROL_URL`, with NM-F-01/02/04-07's ACL policy already pushed (`tag:storage-service` must be able to reach `tag:database-vault` and `tag:certificate-authority`; `tag:storage-access`/`tag:certificate-authority` must be able to reach `tag:storage-service`).
- A single-use Tailscale pre-auth key for Storage-Service's own node, tagged `tag:storage-service` (`docker exec <headscale-container> headscale preauthkeys create --user <id> --tags tag:storage-service`), passed as `RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY`.
- Dev-only mTLS certificates for: Database-Vault's server identity, Database-Vault's outbound client identity toward Storage-Service (organization `DatabaseVault`), Storage-Service's server identity (organization `StorageService`, obtained automatically via CA-F-04's bootstrap-token flow, `RAM_USB_CA_BOOTSTRAP_TOKEN`), and a test-harness client identity standing in for Security-Switch (organization `SecuritySwitch`).
- A second single-use CA-F-04 bootstrap token for `identity-provisioner`, organization `StorageService`, passed as `RAM_USB_STORAGE_SERVICE_AKC_BOOTSTRAP_TOKEN` (`deployments/compose/storage-service.yml` documents the exact `step ca token` minting command), plus `RAM_USB_DATABASE_VAULT_PUBLIC_KEY_URL` pointing at Database-Vault's ST-F-11 lookup listener (e.g. `https://database-vault:8446`).

## `authorized-keys-command.conf` provisioning

ST-F-11's `authorized-keys-command` binary reads its own mTLS identity (certificate, key, CA bundle) and Database-Vault's base URL from a fixed file, `/var/lib/storage-service-identity/authorized-keys-command.conf` (see `services/storage-service/cmd/authorized-keys-command/main.go`'s own package doc comment). The `identity-provisioner` longrun (`services/storage-service/cmd/identity-provisioner/main.go`) writes that file and the three files it points at (`akc-client.crt`, `akc-client.key`, `akc-ca.crt`, same directory): it bootstraps its own mTLS identity from the Certificate-Authority with its own single-use token, writes the config once, and re-encodes the current certificate/key every five minutes so the on-disk copy tracks `pkg/pki`'s automatic renewal. `sshd` starts only once that first write has landed - `rootfs/etc/s6-overlay/s6-rc.d/sshd/dependencies.d/identity-provisioner-ready`, whose oneshot runs `/etc/storage-service/identity-provisioner-ready.sh`. `database_vault_url` in that file is Database-Vault's Tailscale MagicDNS short hostname, resolvable through the container's own OS resolver once `tailscaled` joins (confirmed live: `tailscale up`'s default `--accept-dns=true` replaces `/etc/resolv.conf` with MagicDNS's `100.100.100.100` resolver and the mesh's search domain, and this container's own CA-F-04 bootstrap dial to `certificate-authority` resolves and completes through exactly that path - see "Live verification" below).

## Procedure

1. **Build the image.**
   ```
   docker build -f deployments/docker/storage-service/Dockerfile -t storage-service .
   ```

2. **Run it under the real capability constraint**, via `deployments/compose/storage-service.yml` (`--cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun`). No port is published to the host or `ramusb-net` (NET-F-01) - `sshd` binds `2222` exclusively on the Tailscale interface address, not the standard `22` (`CAP_NET_BIND_SERVICE` is deliberately outside this capability set) and not on any other interface.

3. **Run the real Database-Vault container** (from the prerequisites), joined to the same mesh, with the dev certs and Storage-Service's MagicDNS hostname.

4. **Register a real user.** `POST` Database-Vault's register endpoint, mTLS-authenticated as `SecuritySwitch`, with a real email/password/SSH-public-key payload. Confirm HTTP 201 and a `posix_username` in the response.

5. **Connect via SFTP** as that POSIX user, from another mesh node with reachability toward `tag:storage-service` (e.g. a registered/authenticated User's own node, or the test-harness node used in this procedure), using the private key matching the public key sent at registration. Confirm:
   - the connection succeeds and lands inside the chroot (ST-F-05, ST-F-07)
   - a file written inside `data/` round-trips with identical content (ST-F-02, ST-F-08)
   - a write attempt outside `data/` is refused
   - a plain `ssh` (non-SFTP) session to the same user is refused (ST-F-03, ST-F-04)
   - the server offers only `publickey`/`keyboard-interactive`, never `password`, as an authentication method (ST-F-09)

   `sshd_config` sets `AuthorizedKeysFile none` globally, so every accepted key comes from `AuthorizedKeysCommand` alone (ST-F-11): this step needs a working Database-Vault behind `identity-provisioner`'s config, or a stub in its place. The integration suite's stub form: overwrite `/usr/local/bin/authorized-keys-command` with an `sh` script running `exec cat "/etc/ssh/itest-authorized-keys/$1"`, fixtures under `/etc/ssh` owned by root at mode `0644` (directories `0755`) so the unprivileged `sshd-authkeys` account can read them.

6. **Supervision.** Inside the running container, kill the `storage-service` process. Confirm s6-overlay respawns it within a few seconds, `sshd`, `tailscaled` and `identity-provisioner` stay unaffected throughout, and a fresh request against the create-user endpoint succeeds again once respawned.

7. **Clean shutdown.** `docker stop` the container. Confirm all four longruns receive and act on the termination signal well within the stop timeout (check container logs for an orderly shutdown sequence from `sshd`, `tailscaled`, `identity-provisioner`, and s6-rc).

## Last verified

2026-07-19, against commit `032763c` on `feature/storage-service-os-provisioning`. All seven steps passed on the first attempt, after fixing two `posixuser` bugs found during this same run: the created account's default shadow-field value administratively locked all authentication methods including public-key, and the chroot root's original permission mode blocked the connecting user from traversing into their own `data/` subdirectory. Both are fixed in `services/storage-service/internal/posixuser`.

### Mesh integration (this session)

2026-07-22, live against a real `network-manager-headscale` container and this repository's own `deployments/compose/storage-service.yml`, without a full step 3-5 run (no live Database-Vault registration performed this session). Confirmed:

- `docker exec network-manager-headscale headscale nodes list` shows Storage-Service's node online, tagged `tag:storage-service`, with a real mesh IPv4 address, after `docker compose -f deployments/compose/storage-service.yml up -d --build`.
- `docker logs storage-service` shows `tailscale-up` completing before `sshd`/`storage-service` start (s6-rc dependency ordering), then `Server listening on <mesh-ip> port 2222` and `storage-service: listening addr=<mesh-ip>:8448` - both bound exclusively to the Tailscale interface.
- `docker port storage-service` returns nothing (no published port); from a plain `ramusb-net`-only container, `nc` to both Storage-Service's `ramusb-net` IP and its Docker DNS hostname on port `2222` is refused outright (`Connection refused`), confirming `sshd` no longer listens there at all.
- From a second real-`tailscaled` container correctly configured with `TS_USERSPACE=false` (see the pitfall below) and a pre-auth key tagged `tag:storage-access` (the same ACL-reachability tag NM-F-09 grants a logged-in User's own node), a real OpenSSH client completed the SSH protocol banner/key exchange against Storage-Service's mesh address on port `2222` and received `Permission denied (publickey,keyboard-interactive)` for a nonexistent POSIX username - confirming both real mesh reachability restricted by Headscale's ACL policy (NET-F-01, NM-F-05) and ST-F-09's "no password method offered" guarantee, over the mesh interface exclusively.
- Storage-Service's own CA-F-04 bootstrap dial to `certificate-authority` (a mesh peer joined by a different service's own sidecar container) succeeded through the container's MagicDNS resolver alone (`/etc/resolv.conf` shows only `100.100.100.100`/`fd7a:...::53` after `tailscale up`, no `ramusb-net` DNS at all by that point) - live evidence that `authorized-keys-command`'s own `database_vault_url` resolves the same way.
- **Pitfall, costly to rediscover:** a `tailscale/tailscale:latest` container started via a plain `docker run` (this project's own `deployments/compose/tailscale-test.yml` pattern) defaults to `containerboot`'s **userspace-networking** fallback (`--tun=userspace-networking`) unless `TS_USERSPACE=false` is set explicitly - even with `/dev/net/tun` present and `CAP_NET_ADMIN`/`CAP_NET_RAW` granted. In that mode there is no kernel `tailscale0` interface at all (`ip addr show tailscale0` reports "does not exist"), so `tailscale ping` (WireGuard-encapsulated ICMP, handled entirely by `magicsock` in userspace) succeeds while every real, kernel-routed TCP connection through that node times out - a false negative that looks exactly like a genuine mesh/routing failure. Storage-Service's own `tailscaled` (invoked directly via the CLI in `rootfs/etc/s6-overlay/s6-rc.d/tailscaled/run`, not through `containerboot`) is unaffected - it uses a real kernel TUN device by default. Any future ad-hoc diagnostic Tailscale container in this project needs `TS_USERSPACE=false` or it will falsely appear unreachable.
