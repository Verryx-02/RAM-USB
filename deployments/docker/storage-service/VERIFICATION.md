# Storage-Service container verification

This is the manual system-test procedure for ST-F-02 through ST-F-11's OS-level guarantees: chroot isolation, SFTP-only access, sshd hardening, and public-key resolution via `AuthorizedKeysCommand`. It exercises Storage-Service's real container against a real Database-Vault, per `Test_Plan.md` §2.3's system-test technique (full stack, real mTLS certificates).

## Mesh architecture (NET-F-01)

Unlike Security-Switch/Database-Vault (pure Go binaries, embed `pkg/mesh`'s in-process `tsnet` directly), Storage-Service's container also runs `sshd` - a C binary that needs a genuine kernel network interface, not an in-process Go netstack. This container therefore runs a real, OS-level `tailscaled` client, supervised by s6-overlay alongside `sshd` and the `storage-service` Go binary (see the SRS 4.5 `[!NOTE]`). `tailscaled` joins the mesh once at container start (`tailscale-up` oneshot, `rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/`) and stays up for the container's whole lifetime; `sshd` and `storage-service` both wait on that oneshot (s6-rc dependency) before starting, since both bind exclusively to the discovered Tailscale interface address, never `0.0.0.0`/`ramusb-net`/a host-published port.

## Prerequisites

- Docker.
- A local Postgres instance for Database-Vault: `docker compose -f deployments/compose/postgres.yml up -d`.
- Database-Vault's schema applied. There is currently no automatic migration mechanism (see the project's known-gaps tracking); apply `services/database-vault/migrations/*.sql` manually via `golang-migrate` first.
- A real Headscale instance (`deployments/compose/headscale.yml`) reachable at `RAM_USB_TAILSCALE_CONTROL_URL`, with NM-F-01/02/04-07's ACL policy already pushed (`tag:storage-service` must be able to reach `tag:database-vault` and `tag:certificate-authority`; `tag:storage-access`/`tag:certificate-authority` must be able to reach `tag:storage-service`).
- A single-use Tailscale pre-auth key for Storage-Service's own node, tagged `tag:storage-service` (`docker exec <headscale-container> headscale preauthkeys create --user <id> --tags tag:storage-service`), passed as `RAM_USB_STORAGE_SERVICE_TAILSCALE_AUTHKEY`.
- Dev-only mTLS certificates for: Database-Vault's server identity, Database-Vault's outbound client identity toward Storage-Service (organization `DatabaseVault`), Storage-Service's server identity (organization `StorageService`, obtained automatically via CA-F-04's bootstrap-token flow, `RAM_USB_CA_BOOTSTRAP_TOKEN`), the `authorized-keys-command` binary's outbound client identity toward Database-Vault (organization `StorageService`), and a test-harness client identity standing in for Security-Switch (organization `SecuritySwitch`).

## Known gap: `authorized-keys-command.conf` provisioning

ST-F-11's `authorized-keys-command` binary reads its own mTLS identity (certificate, key, CA bundle) and Database-Vault's base URL from a fixed file, `/etc/storage-service/authorized-keys-command.conf` (see `services/storage-service/cmd/authorized-keys-command/main.go`'s own package doc comment). Minting that binary's own mTLS identity and writing this file is a separate, not-yet-scoped task: no CA-F-04 bootstrap flow or Dockerfile/compose step currently populates it, in this container or in the compose file. Until it is scoped and built, `sshd` correctly fails secure (RD-04) for every SFTP connection attempt - `authorized-keys-command` exits 0 with empty stdout on a missing config file, exactly the same observable behavior as "no key on record" - but no real ST-F-11 round trip to Database-Vault can complete. `database_vault_url` in that file should point to Database-Vault's Tailscale MagicDNS short hostname (e.g. `https://database-vault:8445`) once it exists - resolvable automatically through the container's own OS resolver once `tailscaled` joins (confirmed live this session: `tailscale up`'s default `--accept-dns=true` replaces `/etc/resolv.conf` with MagicDNS's `100.100.100.100` resolver and the mesh's search domain, and this container's own CA-F-04 bootstrap dial to `certificate-authority` already resolves and completes successfully through exactly that path - see "Live verification" below).

## Procedure

1. **Build the image.**
   ```
   docker build -f deployments/docker/storage-service/Dockerfile -t storage-service .
   ```

2. **Run it under the real capability constraint**, via `deployments/compose/storage-service.yml` (`--cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun`). No port is published to the host or `ramusb-net` (NET-F-01) - `sshd` binds `2222` exclusively on the Tailscale interface address, not the standard `22` (`CAP_NET_BIND_SERVICE` is deliberately outside this capability set) and not on any other interface.

3. **Run the real `database-vault` binary**, joined to the same mesh, pointed at the Postgres instance from the prerequisites, the dev certs, and Storage-Service's MagicDNS hostname.

4. **Register a real user.** `POST` Database-Vault's register endpoint, mTLS-authenticated as `SecuritySwitch`, with a real email/password/SSH-public-key payload. Confirm HTTP 201 and a `posix_username` in the response.

5. **Connect via SFTP** as that POSIX user, from another mesh node with reachability toward `tag:storage-service` (e.g. a registered/authenticated User's own node, or the test-harness node used in this procedure), using the private key matching the public key sent at registration. Confirm:
   - the connection succeeds and lands inside the chroot (ST-F-05, ST-F-07)
   - a file written inside `data/` round-trips with identical content (ST-F-02, ST-F-08)
   - a write attempt outside `data/` is refused
   - a plain `ssh` (non-SFTP) session to the same user is refused (ST-F-03, ST-F-04)
   - the server offers only `publickey`/`keyboard-interactive`, never `password`, as an authentication method (ST-F-09)

6. **Two-process supervision.** Inside the running container, kill the `storage-service` process. Confirm s6-overlay respawns it within a few seconds, `sshd` and `tailscaled` stay unaffected throughout, and a fresh request against the create-user endpoint succeeds again once respawned.

7. **Clean shutdown.** `docker stop` the container. Confirm all three processes receive and act on the termination signal well within the stop timeout (check container logs for an orderly shutdown sequence from `sshd`, `tailscaled`, and s6-rc).

## Last verified

2026-07-19, against commit `032763c` on `feature/storage-service-os-provisioning`. All seven steps passed on the first attempt, after fixing two `posixuser` bugs found during this same run: the created account's default shadow-field value administratively locked all authentication methods including public-key, and the chroot root's original permission mode blocked the connecting user from traversing into their own `data/` subdirectory. Both are fixed in `services/storage-service/internal/posixuser`.

### Mesh integration (this session)

2026-07-22, live against a real `network-manager-headscale` container and this repository's own `deployments/compose/storage-service.yml`, without a full step 3-5 run (no live Database-Vault registration performed this session - see the known gap above). Confirmed:

- `docker exec network-manager-headscale headscale nodes list` shows Storage-Service's node online, tagged `tag:storage-service`, with a real mesh IPv4 address, after `docker compose -f deployments/compose/storage-service.yml up -d --build`.
- `docker logs storage-service` shows `tailscale-up` completing before `sshd`/`storage-service` start (s6-rc dependency ordering), then `Server listening on <mesh-ip> port 2222` and `storage-service: listening addr=<mesh-ip>:8448` - both bound exclusively to the Tailscale interface.
- `docker port storage-service` returns nothing (no published port); from a plain `ramusb-net`-only container, `nc` to both Storage-Service's `ramusb-net` IP and its Docker DNS hostname on port `2222` is refused outright (`Connection refused`), confirming `sshd` no longer listens there at all.
- From a second real-`tailscaled` container correctly configured with `TS_USERSPACE=false` (see the pitfall below) and a pre-auth key tagged `tag:storage-access` (the same ACL-reachability tag NM-F-09 grants a logged-in User's own node), a real OpenSSH client completed the SSH protocol banner/key exchange against Storage-Service's mesh address on port `2222` and received `Permission denied (publickey,keyboard-interactive)` for a nonexistent POSIX username - confirming both real mesh reachability restricted by Headscale's ACL policy (NET-F-01, NM-F-05) and ST-F-09's "no password method offered" guarantee, over the mesh interface exclusively.
- Storage-Service's own CA-F-04 bootstrap dial to `certificate-authority` (a mesh peer joined by a different service's own sidecar container) succeeded through the container's MagicDNS resolver alone (`/etc/resolv.conf` shows only `100.100.100.100`/`fd7a:...::53` after `tailscale up`, no `ramusb-net` DNS at all by that point) - live evidence for the "known gap" section's claim that `authorized-keys-command`'s future `database_vault_url` will resolve the same way once its own config-provisioning task exists.
- **Pitfall, costly to rediscover:** a `tailscale/tailscale:latest` container started via a plain `docker run` (this project's own `deployments/compose/tailscale-test.yml` pattern) defaults to `containerboot`'s **userspace-networking** fallback (`--tun=userspace-networking`) unless `TS_USERSPACE=false` is set explicitly - even with `/dev/net/tun` present and `CAP_NET_ADMIN`/`CAP_NET_RAW` granted. In that mode there is no kernel `tailscale0` interface at all (`ip addr show tailscale0` reports "does not exist"), so `tailscale ping` (WireGuard-encapsulated ICMP, handled entirely by `magicsock` in userspace) succeeds while every real, kernel-routed TCP connection through that node times out - a false negative that looks exactly like a genuine mesh/routing failure. Storage-Service's own `tailscaled` (invoked directly via the CLI in `rootfs/etc/s6-overlay/s6-rc.d/tailscaled/run`, not through `containerboot`) is unaffected - it uses a real kernel TUN device by default. Any future ad-hoc diagnostic Tailscale container in this project needs `TS_USERSPACE=false` or it will falsely appear unreachable.
