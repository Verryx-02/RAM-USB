# syntax=docker/dockerfile:1
#
# Network-Manager container image. TWO independent long-lived processes -
# a real `tailscaled` mesh client and this repo's network-manager Go mTLS
# HTTP server (NM-F-03, NM-F-08, NM-F-09) - are supervised by s6-overlay on
# a debian:bookworm-slim base, matching the deployment diagram
# (docs/design/diagrams/02-architecture-deployment.puml's "NetworkManagerDocker"
# node). Headscale itself is NOT part of this image - a prior version of
# this Dockerfile co-located it here; that co-location was withdrawn this
# session after finding Headscale's own documented limitation
# (headscale.net's FAQ): "running headscale on a machine that is also in
# the tailnet it coordinates... is not supported" - Headscale's own
# coordination server can never safely be a member of the mesh it
# coordinates, which co-locating it with this mesh-joined container
# effectively assumed it would be. Headscale is now its own separate
# deployment (deployments/compose/headscale.yml, deployments/docker/
# headscale/ - a reverse proxy plus Headscale itself, no Network-Manager
# code) - see services/network-manager/cmd/network-manager/main.go's own
# package doc comment for the full reasoning and how this container now
# reaches it (a REST call over the public network, through that reverse
# proxy, NOT the mesh - Headscale itself cannot be a mesh member).
#
# This container is now a REGULAR mesh-joined service, structurally
# identical to Security-Switch's own Dockerfile/rootfs (tailscaled +
# trust-mesh-ca + tailscale-up + the service's own Go longrun, no more
# Headscale-specific s6 units) - it dials the separately-deployed Headscale
# for its OWN mesh join (RAM_USB_TAILSCALE_CONTROL_URL) exactly like every
# other mesh-joined service does, no longer "https://localhost:8080".
#
# `tailscaled` (a real, OS-level Tailscale client daemon), not pkg/mesh's
# in-process tsnet: this process needs Certificate-Authority-bootstrap
# traffic (pkg/pki) and MQTT metrics-publish traffic (pkg/metrics) to go
# through the mesh, and neither library exposes a way to route through an
# in-process-only netstack for their internal/background traffic
# (confirmed by direct source reading this session - a hard library
# limitation, not a code gap). A real tailscaled makes the container's
# only network egress a genuine kernel tailscale0 interface, so every
# outbound connection this process makes THROUGH THE MESH - including
# internal library HTTP calls that know nothing about mesh - is forced
# through it automatically, with zero application-level dial injection
# needed. Exactly the same mechanism Storage-Service already uses (see
# that Dockerfile's own package doc comment) for the analogous reason
# (there, sshd needs a kernel TUN device). The one outbound call this
# process makes that deliberately does NOT go through tailscaled/the mesh
# is its own Headscale admin-API REST call (buildHeadscaleAPIClient in
# main.go) - Headscale is not itself a mesh member, so there is no mesh
# path to it at all.
#
# Why debian:bookworm-slim, not distroless (see the [!NOTE] right after the
# SRS's §2's directory-structure diagram for this project's base-image
# policy, RNF-SEC-03): this process needs a real tailscaled + iproute2/
# iptables, which themselves need a real shell/package manager - the same
# reasoning Storage-Service's own Dockerfile documents. distroless has no
# shell, so s6-overlay (the same version already proven working for
# Storage-Service, deployments/docker/storage-service/Dockerfile) is used
# here too. This container runs entirely as root throughout, for
# consistency with Storage-Service - even though nothing here strictly
# needs root beyond tailscaled's own NET_ADMIN/NET_RAW requirement (no
# chroot/setuid/useradd, unlike Storage-Service); revisit this choice if a
# non-root s6-overlay pattern gets established elsewhere in this project.
#
# Runs under a deliberately narrow capability set (wired for real in
# deployments/compose/network-manager.yml):
#
#   --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun
#
# NET_ADMIN/NET_RAW and /dev/net/tun are tailscaled's own minimum
# requirements to create and manage the mesh's TUN network interface -
# same as Storage-Service's identical capability pair.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/mtls, pkg/pki, and
# services/network-manager/... from the module rooted there, not from
# this directory):
#
#   docker build -f deployments/docker/network-manager/Dockerfile \
#       -t ram-usb/network-manager .

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG TAILSCALE_VERSION=1.98.9

# ---- build stage: compile a fully static binary ------------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary, so the runtime stage's glibc
# version never has to match this build stage's - same reasoning as
# Storage-Service's own build stage.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/network-manager \
    ./services/network-manager/cmd/network-manager

# ---- runtime stage -------------------------------------------------------
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TAILSCALE_VERSION
ARG TARGETARCH

# ca-certificates: this process's own outbound calls (Certificate-Authority
# bootstrap, MQTT metrics publish, and Headscale's admin-API REST calls -
# the latter trusting either the real system trust store, in production
# with a real Let's Encrypt reverse-proxy certificate, or a mounted
# dev-only cert via RAM_USB_NETWORK_MANAGER_HEADSCALE_API_CA_FILE) need a
# real trust store; also gives the real tailscaled client a genuine OS
# trust store to extend via update-ca-certificates for the mesh's own
# dev-only self-signed control-plane certificate (see rootfs/etc/
# s6-overlay/s6-rc.d/trust-mesh-ca/) - same reasoning as Storage-Service's
# Dockerfile.
# curl, xz-utils: fetch/extract the s6-overlay and tailscale release
# tarballs below.
# iproute2, iptables: tailscaled's own runtime dependencies for managing
# the TUN interface's routes and (default) netfilter-based packet
# filtering - without them tailscaled never reaches the "Running" state
# (see Storage-Service's Dockerfile for the full reasoning, identical
# here).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the tailscaled/tailscale-up/
# trust-mesh-ca oneshots plus the network-manager longrun. TARGETARCH is
# set automatically by BuildKit to the image's target platform
# (amd64/arm64); mapped here to s6-overlay's own release-asset
# architecture names (x86_64/aarch64) - identical block to Storage-
# Service's Dockerfile.
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
# in-process tsnet). Identical install mechanism to Storage-Service's own
# Dockerfile - see that file's comment for the confirmed tarball layout.
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

# /var/lib/tailscale, /var/run/tailscale: the real tailscaled client's own
# state/socket directories (RAM_USB_NETWORK_MANAGER_TAILSCALE_AUTHKEY's
# join target) - created here (root-owned, this container's only user) so
# they exist even before the named volume in deployments/compose/
# network-manager.yml is mounted over /var/lib/tailscale.
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

COPY --from=build /out/network-manager /usr/local/bin/network-manager
RUN chmod 0755 /usr/local/bin/network-manager

# s6-rc.d service definitions (trust-mesh-ca/tailscaled/tailscale-up
# oneshots plus the network-manager longrun) plus their user-bundle
# membership files - see this directory's own files for the full layout
# s6-overlay's README documents.
COPY deployments/docker/network-manager/rootfs/ /

# NM-F-03's mTLS listener binds only to this node's real Tailscale mesh
# interface address (assigned at runtime by tailscale-up, never a fixed
# value) - no fixed value worth documenting via EXPOSE, and (unlike the
# earlier co-located version of this image) this container publishes
# nothing to the Docker host at all: Headscale's own public coordination
# endpoint now lives in the separate deployments/compose/headscale.yml
# deployment instead.

ENTRYPOINT ["/init"]
