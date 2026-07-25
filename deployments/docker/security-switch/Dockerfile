# syntax=docker/dockerfile:1
#
# Security-Switch container image. TWO independent long-lived processes - a
# real `tailscaled` mesh client and this repo's security-switch Go mTLS
# HTTP server (SS-F-01/04/05/09) - are supervised by s6-overlay on a
# debian:bookworm-slim base, mirroring Storage-Service's exact mechanism
# (deployments/docker/storage-service/Dockerfile) instead of pkg/mesh's
# in-process tsnet.
#
# Why a real tailscaled here now, not pkg/mesh: pkg/mesh's in-process tsnet
# node can only route dials this process's own Go code explicitly passes
# through it (Transport.DialContext). It cannot route two other outbound
# call paths this process also makes: the Certificate-Authority bootstrap/
# renewal exchange (pkg/pki, wraps github.com/smallstep/certificates/ca,
# which builds its own internal transports with no interceptable dial hook
# - see .claude/agent-memory/code-agent.md's "pkg/pki dialer routing"
# section for the confirmed library-source-level limitation) and the MQTT
# metrics-publish connection's underlying dial in some code paths. Giving
# this container a REAL, kernel-level Tailscale network interface instead
# makes every outbound connection the process makes - including internal
# library calls that know nothing about mesh - go through it automatically,
# with zero application-level dial injection needed. There is still no
# sshd, no POSIX user management, no chroot in this image - only
# tailscaled's own minimum requirements (NET_ADMIN/NET_RAW, /dev/net/tun)
# are added beyond what a single Go binary needs.
#
# Build context MUST be the repository root (this Dockerfile builds a
# package that imports pkg/mtls, pkg/pki, pkg/errors, pkg/logging, and
# services/security-switch/... from the module rooted there, not from this
# directory):
#
#   docker build -f deployments/docker/security-switch/Dockerfile \
#       -t ram-usb/security-switch .
#
# Runs under a deliberately narrow capability set (wired for real in
# deployments/compose/security-switch.yml):
#
#   cap_add: [NET_ADMIN, NET_RAW], devices: [/dev/net/tun:/dev/net/tun]
#
# NET_ADMIN/NET_RAW and /dev/net/tun are tailscaled's own minimum
# requirements to create and manage the mesh's TUN network interface - same
# pair already confirmed necessary for Storage-Service's identical
# tailscaled setup.
#
# Runtime configuration is entirely environment-variable driven (see
# main.go's own const block for the full list: RAM_USB_CA_BOOTSTRAP_TOKEN,
# RAM_USB_SECURITY_SWITCH_LISTEN_ADDR (now assembled at container start by
# rootfs/etc/s6-overlay/s6-rc.d/security-switch/run from this node's real
# Tailscale IPv4 address, not passed through verbatim), RAM_USB_DATABASE_VAULT_URL,
# RAM_USB_NETWORK_MANAGER_URL, and the optional RAM_USB_MQTT_* metrics
# variables) - none of it is baked into this image.

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG TAILSCALE_VERSION=1.98.9

# ---- build stage: compile a single static binary -----------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: static binary, avoiding glibc-version coupling between the
# golang:1.26 build image and debian:bookworm-slim's own libc, same
# reasoning as Storage-Service's identical build-stage choice.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/security-switch \
    ./services/security-switch/cmd/security-switch

# ---- runtime stage ------------------------------------------------------
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TAILSCALE_VERSION
ARG TARGETARCH

# xz-utils: needed to extract the .tar.xz s6-overlay release tarballs below.
# curl, ca-certificates: fetch those tarballs over HTTPS, and (ca-certificates)
# give the real tailscaled client a genuine OS trust store to extend via
# update-ca-certificates for Headscale's dev-only self-signed control-plane
# certificate (see rootfs/etc/s6-overlay/s6-rc.d/trust-mesh-ca/) - unlike
# pkg/mesh's distroless SSL_CERT_FILE workaround this container no longer
# uses, this base image has a real shell and package manager, so the
# standard OS-level mechanism applies directly.
# iproute2, iptables: tailscaled's own runtime dependencies for managing the
# TUN interface's routes and (default) netfilter-based packet filtering -
# same confirmed requirement as Storage-Service's identical package list.
#
# Deliberately NOT installed, unlike Storage-Service: openssh-server,
# passwd - this service has no sshd/POSIX-user role, so its package list
# stays minimal to what tailscaled+s6-overlay actually need.
RUN apt-get update && apt-get install -y --no-install-recommends \
    xz-utils \
    curl \
    ca-certificates \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the two longruns (tailscaled,
# security-switch) plus the tailscale-up/trust-mesh-ca oneshots.
# TARGETARCH is set automatically by BuildKit to the image's target
# platform (amd64/arm64); mapped here to s6-overlay's own release-asset
# architecture names (x86_64/aarch64).
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

# tailscale/tailscaled: the real, OS-level mesh client (see this file's own
# package doc comment for why this container needs one instead of pkg/mesh's
# in-process tsnet). pkgs.tailscale.com's static release tarball ships both
# binaries at "tailscale_<version>_<arch>/{tailscale,tailscaled}", same
# confirmed layout as Storage-Service's identical install step. Mapped to
# Tailscale's own release-asset architecture names, which for this tarball
# happen to already match TARGETARCH (amd64/arm64), unlike s6-overlay's
# x86_64/aarch64 naming above.
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
# deployments/compose/security-switch.yml).
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

COPY --from=build /out/security-switch /usr/local/bin/security-switch
RUN chmod 0755 /usr/local/bin/security-switch

# s6-rc.d service definitions (tailscale-up/trust-mesh-ca oneshots,
# tailscaled/security-switch longruns) plus their user-bundle membership
# files - see this directory's own files for the full layout s6-overlay's
# README documents.
COPY deployments/docker/security-switch/rootfs/ /

# No EXPOSE: SS-F-01's listener no longer binds a fixed, build-time-known
# address - it binds to this node's Tailscale mesh interface address,
# assigned only at runtime once tailscaled joins (see
# rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/), so there is no fixed value
# to document via EXPOSE even for documentation purposes.

ENTRYPOINT ["/init"]
