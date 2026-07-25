# syntax=docker/dockerfile:1
#
# Database-Vault container image. This is the vault: the component's own
# name implies it IS the database, not a Go service with a network
# dependency on a separate Postgres container - so Postgres is merged into
# this image and supervised by s6-overlay alongside the database-vault Go
# binary (DV-F-01..DV-F-20), matching the same "no network path exists at
# all, not just a firewall rule" pattern already applied to
# Network-Manager+Headscale. Postgres binds to loopback only (see the
# postgres s6-rc.d longrun's own `run` script) - reachable from nothing but
# this container's own database-vault process, closing a gap the SRS does
# not explicitly name but that the project treats as a genuine security
# requirement given Database-Vault's role (DV-F-08).
#
# This container also joins the private Headscale mesh via a REAL,
# OS-level `tailscaled` daemon (tailscaled/tailscale-up/trust-mesh-ca
# below), the same mechanism already proven for Storage-Service
# (deployments/docker/storage-service/), instead of pkg/mesh's in-process
# tsnet: neither pkg/pki (wraps github.com/smallstep/certificates/ca, the
# Certificate-Authority bootstrap/renewal client) nor pkg/metrics (the MQTT
# metrics-publish client) exposes a way to route their own internal/
# background traffic through an in-process-only netstack - a confirmed
# library limitation, not a code gap (see database-vault Go binary's own
# main.go doc comment and .claude/agent-memory/code-agent.md's "pkg/pki
# dialer routing" notes for the source-level reasons). Making this
# container's only network egress a genuine kernel tailscale0 interface
# forces every outbound connection the database-vault process makes -
# including those two libraries' own internal calls - through the mesh
# automatically, with zero application-level dial injection needed.
#
# Two mTLS HTTP listeners (register/login accepting Security-Switch, over
# the Tailscale mesh interface, and ST-F-11's public-key lookup accepting
# Storage-Service, on ramusb-net, both sharing one CA-bootstrapped identity
# via pkg/pki, CA-F-04), an outbound mTLS client to Storage-Service
# (DV-F-09, over the mesh), the loopback-only Postgres connection
# (DV-F-08), and an automatic schema-migration step at startup
# (internal/schema, applied before this process starts serving).
#
# Unlike the prior distroless runtime stage, this image is built FROM the
# official postgres:17 image itself (Debian-based, already has a correctly
# installed Postgres plus a shell and apt) rather than hand-copying
# Postgres's binaries/shared libraries/locale files into a minimal base -
# that piecemeal approach is fragile given how many file-layout dependencies
# a real Postgres install has. s6-overlay and the database-vault Go binary
# are layered on top, the same structural pattern already used for
# Storage-Service's debian:bookworm-slim image (see
# deployments/docker/storage-service/Dockerfile's own doc comment) - see the
# container base-image policy [!NOTE] after SRS §2.4: this is "a genuine
# OS-level requirement a distroless image cannot satisfy" in exactly the
# sense that note describes, just for an embedded Postgres (and now a real
# tailscaled) rather than Storage-Service's sshd.
#
# Build context MUST be the repository root (this Dockerfile builds a
# package that imports pkg/mtls, pkg/pki, and every services/database-vault/
# internal/... package from the module rooted there, not from this
# directory):
#
#   docker build -f deployments/docker/database-vault/Dockerfile \
#       -t ram-usb/database-vault .
#
# Runtime configuration is entirely environment-variable-driven, per
# cmd/database-vault/main.go's own doc comment (RAM_USB_MASTER_KEY,
# RAM_USB_PASSWORD_PEPPER, RAM_USB_CA_BOOTSTRAP_TOKEN,
# RAM_USB_DATABASE_VAULT_LISTEN_ADDR, RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR,
# RAM_USB_DATABASE_VAULT_DATABASE_URL, RAM_USB_STORAGE_SERVICE_URL, and the
# optional RAM_USB_DATABASE_VAULT_MIGRATIONS_DIR / RAM_USB_MQTT_* group),
# PLUS Postgres's own POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB (consumed
# by the postgres longrun's `run` script, which execs the upstream
# postgres:17 image's own docker-entrypoint.sh so first-run initdb and the
# env-driven bootstrap keep working exactly as upstream intends), PLUS the
# real-tailscaled mesh-membership group (RAM_USB_TAILSCALE_CONTROL_URL,
# RAM_USB_DATABASE_VAULT_TAILSCALE_AUTHKEY, RAM_USB_DATABASE_VAULT_MESH_HOSTNAME,
# RAM_USB_DATABASE_VAULT_LISTEN_PORT) - wired for real in
# deployments/compose/database-vault.yml. RAM_USB_DATABASE_VAULT_LISTEN_ADDR
# itself is no longer passed through Compose: the database-vault longrun's
# own `run` script assembles it at container start from
# RAM_USB_DATABASE_VAULT_TAILSCALE_IP (written by the tailscale-up oneshot)
# plus RAM_USB_DATABASE_VAULT_LISTEN_PORT, mirroring Storage-Service's own
# storage-service longrun. No cert/key files are baked into or mounted onto
# this image: this service's TLS identity is obtained at startup from the
# Certificate-Authority via pkg/pki's bootstrap-token flow (CA-F-04,
# PKI-F-01), not from disk.

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG TAILSCALE_VERSION=1.98.9

# ---- build stage: compile a single static binary -----------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary, so the runtime stage's distroless
# base (which has no libc, no shell, no package manager - see below) needs
# nothing beyond the binary itself to run it.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/database-vault \
    ./services/database-vault/cmd/database-vault

# ---- runtime stage -------------------------------------------------------
# postgres:17 (Debian-based, already has a correctly installed Postgres plus
# a shell and apt) rather than gcr.io/distroless/static-debian12:nonroot:
# this image now has a genuine OS-level requirement a distroless image
# cannot satisfy - an embedded Postgres server plus a real tailscaled - per
# the container base-image policy [!NOTE] after SRS §2.4. Everything in this
# stage runs as root: s6-overlay's own supervisor process needs it, and the
# upstream postgres image's own docker-entrypoint.sh already internally
# drops privilege to its own unprivileged "postgres" system user for initdb
# and the server process regardless of the caller's UID (confirmed by
# reading that script: `if [ "$(id -u)" = '0' ]; then exec gosu postgres
# ...`), so this does not weaken Postgres's own process isolation - it
# matches upstream's own design instead of fighting it, the same
# root-everything precedent Storage-Service's debian:bookworm-slim image
# already established for this codebase.
FROM postgres:17
ARG S6_OVERLAY_VERSION
ARG TAILSCALE_VERSION
ARG TARGETARCH

# curl, xz-utils: fetch and extract the s6-overlay/tailscale release
# tarballs below (xz-utils is already present transitively via postgres:17's
# own dependencies - confirmed via `dpkg -S /usr/bin/xz` this session -
# listed explicitly so this Dockerfile does not depend on that remaining
# true). ca-certificates: gives the database-vault Go binary's own outbound
# mTLS calls (Certificate-Authority bootstrap, Storage-Service, the MQTT
# broker) AND the real tailscaled's own control-plane TLS dial a real OS
# trust store; confirmed NOT already present in postgres:17 (no
# update-ca-certificates binary, empty /etc/ssl/certs). iproute2, iptables:
# tailscaled's own runtime dependencies for managing the TUN interface's
# routes and (default) netfilter-based packet filtering - same requirement
# already documented in Storage-Service's own Dockerfile.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    ca-certificates \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the postgres/database-vault longruns
# plus the postgres-ready oneshot, now joined by the tailscaled longrun and
# tailscale-up/trust-mesh-ca oneshots (see rootfs/etc/s6-overlay/s6-rc.d/).
# Identical mechanism to
# deployments/docker/storage-service/Dockerfile's own s6-overlay install -
# see that file's comment for why TARGETARCH is mapped to x86_64/aarch64
# here (s6-overlay's own release-asset architecture names) rather than used
# as-is.
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) S6_ARCH=x86_64 ;; \
      arm64) S6_ARCH=aarch64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/s6-overlay-noarch.tar.xz \
      "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz"; \
    curl -fsSL -o /tmp/s6-overlay-arch.tar.xz \
      "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz"; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz; \
    rm -f /tmp/s6-overlay-noarch.tar.xz /tmp/s6-overlay-arch.tar.xz

# tailscale/tailscaled: the real, OS-level mesh client - identical install
# mechanism and pinned TAILSCALE_VERSION to
# deployments/docker/storage-service/Dockerfile's own tailscale install
# (see that file's own comment for why the release tarball's own arch
# naming, unlike s6-overlay's, already matches TARGETARCH verbatim).
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) TS_ARCH=amd64 ;; \
      arm64) TS_ARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/tailscale.tgz \
      "https://pkgs.tailscale.com/stable/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}.tgz"; \
    tar -C /tmp -xzf /tmp/tailscale.tgz; \
    install -m 0755 "/tmp/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}/tailscale" /usr/sbin/tailscale; \
    install -m 0755 "/tmp/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}/tailscaled" /usr/sbin/tailscaled; \
    rm -rf /tmp/tailscale.tgz "/tmp/tailscale_${TAILSCALE_VERSION}_${TS_ARCH}"

# tailscaled's own state/socket directories - created here so they exist
# with the right ownership (root, this container's only user) even before
# any named volume is mounted over /var/lib/tailscale (see
# deployments/compose/database-vault.yml), same precedent as
# Storage-Service's own Dockerfile.
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

# WORKDIR is set to /app, and the migrations directory below is copied in
# at the SAME relative path (services/database-vault/migrations) that
# cmd/database-vault/main.go's defaultMigrationsDir constant expects
# ("services/database-vault/migrations", a path relative to the process's
# cwd, matching a bare-metal/local run from the repository root - see that
# constant's own doc comment). This keeps the image's on-disk layout a
# strict subset of the repository's own layout rooted at /app, so
# RAM_USB_DATABASE_VAULT_MIGRATIONS_DIR needs no override here - a change
# to WORKDIR alone would have been the other option, but preserving the
# real repo-relative path is less surprising to anyone cross-referencing
# main.go's constant against this image's contents. s6-overlay's own `/init`
# entrypoint does not care about WORKDIR (each s6-rc.d `run` script execs an
# absolute path), so this is purely for database-vault's own migrations
# lookup.
WORKDIR /app

COPY --from=build /out/database-vault /app/database-vault
COPY services/database-vault/migrations /app/services/database-vault/migrations

# s6-rc.d service definitions (postgres longrun wrapping the upstream
# image's own docker-entrypoint.sh, postgres-ready oneshot, the real
# tailscaled longrun plus tailscale-up/trust-mesh-ca oneshots, database-vault
# longrun) plus their user-bundle membership files - see this directory's
# own files for the full layout s6-overlay's README documents.
COPY deployments/docker/database-vault/rootfs/ /

# No EXPOSE: neither Postgres nor database-vault's register/login listener
# publish a host/ramusb-net port (NET-F-01) - Postgres binds to loopback
# only (see rootfs/etc/s6-overlay/s6-rc.d/postgres/run) and the register/
# login listener binds exclusively to this node's real Tailscale interface
# address, assigned only at runtime once tailscaled joins (see
# rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/up), so there is no fixed
# value to document via EXPOSE even for documentation purposes. ST-F-11's
# public-key listener remains on ramusb-net per its own
# RAM_USB_DATABASE_VAULT_PUBLIC_KEY_LISTEN_ADDR env var, wired in
# deployments/compose/database-vault.yml, not here.

ENTRYPOINT ["/init"]
