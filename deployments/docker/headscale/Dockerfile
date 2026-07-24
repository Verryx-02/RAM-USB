# syntax=docker/dockerfile:1
#
# Standalone Headscale deployment - Headscale itself (loopback-only,
# 127.0.0.1:8081) plus an nginx reverse proxy (0.0.0.0:8080, published),
# no RAM-USB Go code at all. TWO long-lived processes, supervised by
# s6-overlay on a debian:bookworm-slim base - same supervision mechanism
# as every other multi-process container in this project (Storage-Service,
# Network-Manager, Database-Vault), chosen for the same reason: a real
# startup-order dependency (nginx must not start proxying before Headscale
# is actually accepting connections) that only a supervisor with a shell
# can express.
#
# # Why Headscale is no longer co-located with Network-Manager
#
# headscale.net's own FAQ documents a hard limitation: "running headscale
# on a machine that is also in the tailnet it coordinates... is not
# supported." Headscale's own coordination server can never safely be a
# member of the private mesh it coordinates - so it cannot be co-located
# inside any RAM-USB service's container, all of which ARE mesh members.
# This container is deliberately NOT a mesh node at all (no tailscaled, no
# pkg/mesh) - see services/network-manager/cmd/network-manager/main.go's
# own package doc comment for the full architectural reasoning and how
# Network-Manager now reaches this container's admin API instead (a REST
# call over the public network, never the mesh).
#
# # NM-F-12/NM-F-14: one public port, two enforcement regimes
#
# NM-F-14 requires Headscale's coordination endpoint to be public-facing
# (ideally on its own dedicated VPS - ARG/env HEADSCALE_HOSTNAME-shaped
# values below are this project's dev/test placeholders, ops-decided in
# production). NM-F-12 requires pre-auth-key/ACL-tag administration
# (Headscale's own `/api/v1/*` REST surface) be restricted to Network-
# Manager specifically, verified via mutual TLS - but Headscale itself
# does not expose any way to separate that surface from its coordination
# protocol by LISTENER: confirmed by reading github.com/juanfont/
# headscale@v0.29.2's hscontrol/app.go this session - `/api/v1/*` (a
# grpc-gateway-generated REST/JSON surface) is registered on the exact
# SAME chi.Router, served on the exact SAME net.Listener (h.cfg.Addr, i.e.
# `listen_addr`), as every coordination-protocol route (/key, /ts2021,
# /register/{id}, ...); Headscale's separate gRPC listener
# (`grpc_listen_addr`) has no path structure to distinguish requests by at
# all, and this session removed every RAM-USB use of it anyway (see
# services/network-manager/internal/headscale/client.go's own package doc
# comment) precisely because REST is what makes this per-path dispatch
# possible in the first place.
#
# nginx.conf (this directory) implements the resulting design: Headscale
# itself runs PLAIN HTTP, loopback-only (127.0.0.1:8081 -
# third-party/headscale/config/config.yaml leaves tls_cert_path/
# tls_key_path empty, Headscale's own documented "run behind a reverse
# proxy" mode) - nginx is the only thing that can reach it, and nginx is
# the only thing this container exposes to the network at all (0.0.0.0:
# 8080). nginx terminates TLS for that one public port with an ORDINARY
# public-style certificate (self-signed dev-only in this project's Compose
# stack, via third-party/headscale/dev-tls - a real Let's Encrypt
# certificate in production) - deliberately NEVER RAM-USB's own internal
# Certificate-Authority: real end-user Tailscale clients (this system's
# own Users, CL-F-04) must be able to trust this certificate too, and have
# no reason to ever trust RAM-USB's private internal CA. `/api/v1/*`
# ADDITIONALLY requires and verifies a client certificate ISSUED BY
# RAM-USB's internal CA, whose organization is exactly "NetworkManager"
# (PKI-F-02) - every other path never asks for one. See nginx.conf's own
# doc comment for the exact mechanism ("ssl_verify_client optional" at the
# server level, enforced per-location instead) and why it is necessary,
# not merely a stylistic choice: TLS client-certificate verification
# happens during the handshake, before nginx has parsed any HTTP path, so
# it cannot vary by `location` the way ordinary request handling can - a
# naive "require a client cert on this listener" would break NM-F-14's
# "open to anyone" coordination endpoint outright.
#
# Both the per-path mTLS enforcement above (verified live via `openssl
# s_client`/`curl --cert`, with and without a certificate, against a real
# running container this session) and the reverse-proxy design as a whole
# were verified against a real container, not written from documentation
# alone - see nginx.conf's own doc comment for the exact
# $ssl_client_verify/$ssl_client_s_dn variable format this session
# confirmed empirically.
#
# Build context MUST be the repository root (this Dockerfile's rootfs COPY
# and nginx.conf both live under deployments/docker/headscale/, but no Go
# code is built here - build context is still the repo root purely for
# this project's own "always build from root" convention, matching every
# other Dockerfile):
#
#   docker build -f deployments/docker/headscale/Dockerfile \
#       -t ram-usb/headscale .

ARG HEADSCALE_VERSION=0.29
ARG S6_OVERLAY_VERSION=3.2.3.2

# ---- headscale-src stage: source of the official Headscale binary ------
# headscale/headscale is a ko-built image; its binary lives at
# /ko-app/headscale.
FROM headscale/headscale:${HEADSCALE_VERSION} AS headscale-src

# ---- runtime stage -------------------------------------------------------
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TARGETARCH

# ca-certificates: Headscale's own config.yaml sets derp.urls to
# https://controlplane.tailscale.com/derpmap/default, an outbound HTTPS
# call at Headscale startup that needs a real trust store.
# curl, xz-utils: fetch/extract the s6-overlay release tarball below, and
# (curl) headscale-ready.sh's own readiness poll.
# nginx: this container's reverse proxy - see this file's own top-level
# doc comment for why it exists and exactly what it enforces.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the headscale/headscale-ready/nginx
# services. TARGETARCH is set automatically by BuildKit to the image's
# target platform (amd64/arm64); mapped here to s6-overlay's own
# release-asset architecture names (x86_64/aarch64) - identical block to
# every other s6-overlay-based Dockerfile in this project.
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

# /var/lib/headscale: Headscale's SQLite data dir + noise private key path
# (third-party/headscale/config/config.yaml). Created here (root-owned,
# this container's only user) so it exists even before the named volume in
# deployments/compose/headscale.yml is mounted over it. www-data (nginx's
# own default user, matching the "user nginx;" directive nginx.conf
# actually sets - Debian's nginx package creates this user at install
# time) needs no directory created here of its own: it proxies only, it
# never writes to disk.
RUN mkdir -p /var/lib/headscale

COPY --from=headscale-src /ko-app/headscale /usr/local/bin/headscale
RUN chmod 0755 /usr/local/bin/headscale

# nginx.conf replaces Debian's own default (which listens on 80 with a
# static-file server block irrelevant to this container).
COPY deployments/docker/headscale/nginx.conf /etc/nginx/nginx.conf

# s6-rc.d service definitions (headscale/headscale-ready/nginx) plus their
# user-bundle membership files, and headscale-ready.sh's own readiness
# script - see this directory's own files for the full layout s6-overlay's
# README documents.
COPY deployments/docker/headscale/rootfs/ /

# Headscale's own coordination/REST-API listener (127.0.0.1:8081, plain
# HTTP) has no fixed value worth documenting via EXPOSE, and is never
# reachable from outside this container regardless (loopback-only). nginx
# (0.0.0.0:8080) is this container's one deliberately public surface -
# NM-F-14, matching every other deliberately public service's own
# Dockerfile convention (e.g. Entry-Hub's own EXPOSE 8443).
EXPOSE 8080

ENTRYPOINT ["/init"]
