# Storage-Service container verification

This is the manual system-test procedure for ST-F-02 through ST-F-11's OS-level guarantees: chroot isolation, SFTP-only access, sshd hardening, and public-key resolution via `AuthorizedKeysCommand`. It exercises Storage-Service's real container against a real Database-Vault, per `Test_Plan.md` §2.3's system-test technique (full stack, real mTLS certificates).

## Prerequisites

- Docker.
- A local Postgres instance for Database-Vault: `docker compose -f deployments/docker-compose.dev.yml up -d database-vault-postgres`.
- Database-Vault's schema applied. There is currently no automatic migration mechanism (see the project's known-gaps tracking); apply `services/database-vault/migrations/*.sql` manually via `golang-migrate` first.
- Dev-only mTLS certificates for: Database-Vault's server identity, Database-Vault's outbound client identity toward Storage-Service (organization `DatabaseVault`), Storage-Service's server identity (organization `StorageService`), the `authorized-keys-command` binary's outbound client identity toward Database-Vault (organization `StorageService`), and a test-harness client identity standing in for Security-Switch (organization `SecuritySwitch`).

## Procedure

1. **Build the image.**
   ```
   docker build -t storage-service -f deployments/docker/storage-service/Dockerfile .
   ```

2. **Run it under the real capability constraint.**
   ```
   docker run --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID --cap-add SYS_CHROOT ...
   ```
   Publish the mTLS port and SFTP port `2222`. sshd binds `2222` internally, not the standard `22`: `CAP_NET_BIND_SERVICE` is deliberately outside this capability set, so a privileged port bind is not available (documented in the SRS's Storage-Service container-architecture note).

3. **Run the real `database-vault` binary** as a host process, pointed at the Postgres instance from the prerequisites, the dev certs, and Storage-Service's published mTLS port.

4. **Register a real user.** `POST` Database-Vault's register endpoint, mTLS-authenticated as `SecuritySwitch`, with a real email/password/SSH-public-key payload. Confirm HTTP 201 and a `posix_username` in the response.

5. **Connect via SFTP** as that POSIX user, using the private key matching the public key sent at registration. Confirm:
   - the connection succeeds and lands inside the chroot (ST-F-05, ST-F-07)
   - a file written inside `data/` round-trips with identical content (ST-F-02, ST-F-08)
   - a write attempt outside `data/` is refused
   - a plain `ssh` (non-SFTP) session to the same user is refused (ST-F-03, ST-F-04)
   - the server offers only `publickey`/`keyboard-interactive`, never `password`, as an authentication method (ST-F-09)

6. **Two-process supervision.** Inside the running container, kill the `storage-service` process. Confirm s6-overlay respawns it within a few seconds, `sshd` stays unaffected throughout, and a fresh request against the create-user endpoint succeeds again once respawned.

7. **Clean shutdown.** `docker stop` the container. Confirm both processes receive and act on the termination signal well within the stop timeout (check container logs for an orderly shutdown sequence from both `sshd` and s6-rc).

## Last verified

2026-07-19, against commit `032763c` on `feature/storage-service-os-provisioning`. All seven steps passed on the first attempt, after fixing two `posixuser` bugs found during this same run: the created account's default shadow-field value administratively locked all authentication methods including public-key, and the chroot root's original permission mode blocked the connecting user from traversing into their own `data/` subdirectory. Both are fixed in `services/storage-service/internal/posixuser`.
