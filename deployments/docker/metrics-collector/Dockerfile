# syntax=docker/dockerfile:1
#
# Metrics-Collector container image. This is now a single self-contained
# service - TimescaleDB is merged into this same container (co-located,
# not a separate `metrics-collector-timescaledb` Compose project/guest),
# the same "absorb the third-party server into one image" pattern already
# used for Database-Vault+Postgres
# (deployments/docker/database-vault/Dockerfile) and Network-Manager+
# Headscale (deployments/docker/network-manager/Dockerfile) - see
# docs/Known_Issues.md's KI-18 for the decision record. This file is the
# SOLE place RAM_USB_METRICS_COLLECTOR_POSTGRES_PASSWORD is generated and
# used now - no separate metrics-collector-timescaledb.yml Compose
# project, no cross-shell/cross-project requirement to export the
# identical password value twice.
#
# Unlike Database-Vault's own Postgres (loopback-only, reachable from
# nothing but that container's own Go binary), TimescaleDB here must stay
# reachable from ANOTHER guest in production: Grafana's own outbound query
# connection (MT-F-04, UC-05, RU-10) is a direct Postgres-wire connection
# to TimescaleDB, not a call routed through Metrics-Collector's own Go
# process, and RNF-ORG-04 places Grafana on its own separate Proxmox
# guest. So this container ALSO joins the private Headscale mesh via a
# real, OS-level `tailscaled` daemon (tailscaled/tailscale-up/
# trust-mesh-ca below, identical mechanism to Database-Vault's own), and
# TimescaleDB binds to every local interface (see the timescaledb longrun's
# own `run` script for why "every local interface" here still means
# "loopback plus this node's mesh interface only" in production, not a
# general network exposure) instead of Database-Vault's loopback-only
# restriction - deployments/compose/metrics-collector.yml documents the
# dev-stack-only caveat this implies (this container still also attaches
# ramusb-net there, for CA-token minting/MQTT reachability, same as every
# other real-tailscaled service in this project).
#
# Metrics-Collector's own Go binary (services/metrics-collector/cmd/
# metrics-collector) has no inbound listener of its own (see that binary's
# own package doc comment) - it only makes two outbound connections, an
# mTLS MQTT subscribe (MT-F-01) and a Postgres/TimescaleDB write (MT-F-03),
# both now reachable without leaving this container (the MQTT connection
# still crosses the mesh/ramusb-net to reach the broker; the database
# connection is now "localhost", see deployments/compose/
# metrics-collector.yml).
#
# Unlike the prior distroless runtime stage, this image is built FROM the
# official timescale/timescaledb image itself (Debian/Postgres-based,
# already has a correctly installed TimescaleDB extension plus a shell and
# apt) rather than hand-copying TimescaleDB's binaries/shared libraries
# into a minimal base - the same "build FROM the official upstream image
# itself rather than hand-copying binaries/libs onto a minimal base -
# piecemeal copying is fragile" reasoning Database-Vault's own Dockerfile
# documents for Postgres. s6-overlay and the metrics-collector Go binary
# are layered on top.
#
# Build context MUST be the repository root (this Dockerfile builds a
# package that imports pkg/metrics, pkg/pki, and every
# services/metrics-collector/internal/... package from the module rooted
# there, not from this directory):
#
#   docker build -f deployments/docker/metrics-collector/Dockerfile \
#       -t ram-usb/metrics-collector .
#
# Runtime configuration is entirely environment-variable-driven, per
# cmd/metrics-collector/main.go's own doc comment
# (RAM_USB_MQTT_BROKER_URL, RAM_USB_CA_BOOTSTRAP_TOKEN,
# RAM_USB_METRICS_COLLECTOR_DATABASE_URL, and the optional
# RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR), PLUS TimescaleDB's own
# POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB (consumed by the timescaledb
# longrun's `run` script, which execs the upstream image's own
# docker-entrypoint.sh so first-run initdb and the env-driven bootstrap
# keep working exactly as upstream intends), PLUS the real-tailscaled
# mesh-membership group (RAM_USB_TAILSCALE_CONTROL_URL,
# RAM_USB_METRICS_COLLECTOR_TAILSCALE_AUTHKEY,
# RAM_USB_METRICS_COLLECTOR_MESH_HOSTNAME) - wired for real in
# deployments/compose/metrics-collector.yml. No cert/key files are baked
# into or mounted onto this image: Metrics-Collector's own mTLS identity
# is obtained at startup from the Certificate-Authority via pkg/pki's
# bootstrap-token flow (CA-F-04, PKI-F-01), not from disk.

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG TAILSCALE_VERSION=1.98.9
ARG TIMESCALEDB_IMAGE=timescale/timescaledb:2.23.0-pg18

# ---- build stage: compile a single static binary -----------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary, so the runtime stage needs nothing
# beyond the binary itself and the migrations directory copied below to
# run it.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/metrics-collector \
    ./services/metrics-collector/cmd/metrics-collector

# ---- runtime stage -------------------------------------------------------
# timescale/timescaledb (Debian/postgres-based, already has a correctly
# installed TimescaleDB extension plus a shell and apt) rather than
# gcr.io/distroless/static-debian12:nonroot: this image now has a genuine
# OS-level requirement a distroless image cannot satisfy - an embedded
# TimescaleDB server plus a real tailscaled - per the container base-image
# policy [!NOTE] after SRS §2.4, same reasoning class as Database-Vault's
# own Dockerfile. Everything in this stage runs as root: s6-overlay's own
# supervisor process needs it, and the upstream postgres/timescaledb
# image's own docker-entrypoint.sh already internally drops privilege to
# its own unprivileged "postgres" system user for initdb and the server
# process regardless of the caller's UID, so this does not weaken
# TimescaleDB's own process isolation - it matches upstream's own design
# instead of fighting it.
FROM ${TIMESCALEDB_IMAGE}
ARG S6_OVERLAY_VERSION
ARG TAILSCALE_VERSION
ARG TARGETARCH

# Unlike Database-Vault's own postgres:17 base (Debian, apt), the official
# timescale/timescaledb image is Alpine-based (confirmed live this
# session: /etc/os-release reports Alpine 3.21, /sbin/apk present,
# /usr/bin/apt-get absent) - apk, not apt-get, and Alpine's own package
# names (xz instead of xz-utils; every other name matches).
#
# curl, xz: fetch and extract the s6-overlay/tailscale release tarballs
# below. ca-certificates: gives the metrics-collector Go binary's own
# outbound mTLS calls (Certificate-Authority bootstrap, the MQTT broker)
# AND the real tailscaled's own control-plane TLS dial a real OS trust
# store. iproute2, iptables: tailscaled's own runtime dependencies for
# managing the TUN interface's routes and (default) netfilter-based
# packet filtering - same requirement already documented in
# Database-Vault's and Storage-Service's own Dockerfiles.
RUN apk add --no-cache \
    curl \
    xz \
    ca-certificates \
    iproute2 \
    iptables

# s6-overlay: process supervision for the timescaledb/metrics-collector
# longruns plus the timescaledb-ready oneshot, joined by the tailscaled
# longrun and tailscale-up/trust-mesh-ca oneshots (see
# rootfs/etc/s6-overlay/s6-rc.d/) - identical mechanism to
# deployments/docker/database-vault/Dockerfile's own s6-overlay install
# (see that file's comment for why TARGETARCH is mapped to
# x86_64/aarch64 here).
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
# deployments/docker/database-vault/Dockerfile's own tailscale install.
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
# deployments/compose/metrics-collector.yml), same precedent as
# Database-Vault's own Dockerfile.
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

# WORKDIR is set to /app, and the migrations directory below is copied in
# at the SAME relative path (services/metrics-collector/migrations) that
# cmd/metrics-collector/main.go's defaultMigrationsDir constant expects -
# same reasoning as Database-Vault's own Dockerfile comment above its own
# migrations COPY (a longrun's exec'd binary does not reliably inherit
# WORKDIR under s6-overlay - see the metrics-collector longrun's own `run`
# script for the corresponding `cd /app`).
WORKDIR /app

COPY --from=build /out/metrics-collector /app/metrics-collector
COPY services/metrics-collector/migrations /app/services/metrics-collector/migrations

# s6-rc.d service definitions (timescaledb longrun wrapping the upstream
# image's own docker-entrypoint.sh, timescaledb-ready oneshot, the real
# tailscaled longrun plus tailscale-up/trust-mesh-ca oneshots,
# metrics-collector longrun) plus their user-bundle membership files.
COPY deployments/docker/metrics-collector/rootfs/ /

# No EXPOSE: TimescaleDB is never published on a host/ramusb-net port
# (NET-F-01) - see the timescaledb longrun's own `run` script for exactly
# what interfaces it does bind to and why. Metrics-Collector's own Go
# binary has no listener of any kind.

ENTRYPOINT ["/init"]
