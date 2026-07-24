# syntax=docker/dockerfile:1
#
# Storage-Service container image. FOUR independent long-lived processes -
# a real `tailscaled` mesh client, a hardened sshd (ST-F-03/04/07/08/09),
# this repo's storage-service Go mTLS HTTP server (ST-F-01/06/10), and
# cmd/identity-provisioner (ST-F-11, KI-01) - are supervised by s6-overlay
# on a debian:bookworm-slim base, per the SRS 4.5 [!NOTE] right after
# Storage-Service's directory-structure diagram. ST-F-11's
# authorized-keys-command binary is installed alongside but is NOT a
# supervised service: sshd invokes it once per SFTP connection attempt, via
# the AuthorizedKeysCommand directive in sshd_config (see that file for the
# full directive set) - identity-provisioner is the separate, long-lived
# process that keeps authorized-keys-command's own mTLS identity/config
# file on disk current (see cmd/identity-provisioner/main.go's own package
# doc comment for why authorized-keys-command cannot bootstrap that
# identity itself).
#
# `tailscaled` (a real, OS-level Tailscale client daemon), not pkg/mesh's
# in-process tsnet: unlike Security-Switch/Database-Vault (pure Go
# binaries, embed tsnet directly), this container also runs sshd - a C
# binary that needs a genuine kernel network interface to bind and accept
# connections on, which only a real tailscaled + /dev/net/tun can provide.
# sshd and storage-service both wait on the tailscale-up oneshot (see
# rootfs/etc/s6-overlay/s6-rc.d/) before starting, since both bind
# exclusively to the mesh interface address once it joins (NET-F-01) -
# tailscaled joins the mesh once at container start and stays up for the
# container's lifetime, not per-connection.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/mtls, pkg/errors, and services/storage-service/...
# from the module rooted there, not from this directory):
#
#   docker build -f deployments/docker/storage-service/Dockerfile \
#       -t ram-usb/storage-service .
#
# Runs under a deliberately narrow capability set (wired for real in
# deployments/compose/storage-service.yml):
#
#   --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
#       --cap-add SYS_CHROOT --cap-add NET_ADMIN --cap-add NET_RAW
#   --device /dev/net/tun
#
# NET_ADMIN/NET_RAW and /dev/net/tun are tailscaled's own minimum
# requirements to create and manage the mesh's TUN network interface -
# confirmed against the working deployments/compose/tailscale-test.yml
# reference container, which uses the identical capability/device pair.
#
# This is why sshd listens on port 2222, not 22: CAP_NET_BIND_SERVICE is
# deliberately not in that set, and without it even UID 0 cannot bind a
# port below 1024 inside the container (verified empirically this session -
# see the code-agent report/memory for the observed failure on :22 and
# success on :2222 under this exact capability set).

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2
ARG TAILSCALE_VERSION=1.98.9

# ---- build stage: compile both Go binaries this image ships -----------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: static binaries, so there is no glibc-version coupling
# between the golang:1.26 build image and debian:bookworm-slim's own libc -
# avoids a whole class of "works in the build stage, missing symbol version
# at runtime" failure when the two base images' glibc versions drift.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/storage-service \
    ./services/storage-service/cmd/storage-service
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/authorized-keys-command \
    ./services/storage-service/cmd/authorized-keys-command
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/identity-provisioner \
    ./services/storage-service/cmd/identity-provisioner

# ---- runtime stage ------------------------------------------------------
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TAILSCALE_VERSION
ARG TARGETARCH

# openssh-server: sshd + ssh-keygen (ST-F-03/04/07/08/09).
# passwd: useradd/groupadd, the tools services/storage-service/internal/posixuser
# shells out to (ST-F-06) - already Debian-"essential" in most images, listed
# explicitly so this Dockerfile does not depend on that remaining true.
# xz-utils: needed to extract the .tar.xz s6-overlay release tarballs below.
# curl, ca-certificates: fetch those tarballs over HTTPS, and (ca-certificates)
# give the real tailscaled client a genuine OS trust store to extend via
# update-ca-certificates for Headscale's dev-only self-signed control-plane
# certificate (see rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/up) - unlike
# pkg/mesh's distroless SSL_CERT_FILE workaround (Security-Switch/
# Database-Vault), this base image has a real shell and package manager, so
# the standard OS-level mechanism applies directly, confirmed by reading
# tailscaled's own client code: like tsnet, it never sets tls.Config.RootCAs
# for its control-plane dial, so it falls back to crypto/x509.SystemCertPool
# exactly like tsnet does.
# iproute2, iptables: tailscaled's own runtime dependencies for managing the
# TUN interface's routes and (default) netfilter-based packet filtering -
# without them tailscaled logs a fatal "prog not found"/"ip: not found"
# error and never reaches the "Running" state. Confirmed necessary by
# reading tailscaled's netns/router packages (Linux router implementation
# shells out to both binaries) - the reference tailscale/tailscale:latest
# image (deployments/compose/tailscale-test.yml) bundles both for the same
# reason.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    passwd \
    xz-utils \
    curl \
    ca-certificates \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the three longruns (tailscaled, sshd,
# storage-service) plus the sshd-hostkeys/tailscale-up oneshots. TARGETARCH
# is set automatically by BuildKit to the image's target platform
# (amd64/arm64); mapped here to s6-overlay's own release-asset architecture
# names (x86_64/aarch64).
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
# binaries at "tailscale_<version>_<arch>/{tailscale,tailscaled}" - confirmed
# by downloading and inspecting the real amd64/arm64 tarballs for
# TAILSCALE_VERSION this session. Mapped to Tailscale's own release-asset
# architecture names, which for this tarball happen to already match
# TARGETARCH (amd64/arm64), unlike s6-overlay's x86_64/aarch64 naming above.
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
# deployments/compose/storage-service.yml).
RUN mkdir -p /var/lib/tailscale /var/run/tailscale

# AuthorizedKeysCommand runs as this dedicated, unprivileged system account
# (per this session's task instructions), with no other role on the
# container - sshd_config's AuthorizedKeysCommandUser directive names it.
# cmd/identity-provisioner (ST-F-11, KI-01) runs as this SAME account too
# (see its own package doc comment for why): the only two things it needs
# are outbound mTLS calls and write access to /etc/storage-service, exactly
# the same unprivileged scope authorized-keys-command itself already has.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sshd-authkeys

# /storage: root of all users (SRS 4.5's directory-structure diagram).
# /etc/storage-service: holds authorized-keys-command.conf plus the
# cert/key/CA-root files cmd/identity-provisioner writes into it (ST-F-11,
# KI-01).
RUN mkdir -p /storage /etc/storage-service

COPY --from=build /out/storage-service /usr/local/bin/storage-service
COPY --from=build /out/authorized-keys-command /usr/local/bin/authorized-keys-command
COPY --from=build /out/identity-provisioner /usr/local/bin/identity-provisioner
# sshd(8)/sshd_config(5) refuses an AuthorizedKeysCommand binary that is
# group- or world-writable. COPY already leaves these root-owned; chmod
# 0755 makes the "not group/world-writable" property explicit rather than
# relying on COPY's default.
RUN chmod 0755 /usr/local/bin/storage-service /usr/local/bin/authorized-keys-command /usr/local/bin/identity-provisioner

COPY deployments/docker/storage-service/sshd_config /etc/ssh/sshd_config

# s6-rc.d service definitions (sshd-hostkeys/tailscale-up oneshots,
# tailscaled/sshd/storage-service longruns) plus their user-bundle
# membership files - see this directory's own files for the full layout
# s6-overlay's README documents.
COPY deployments/docker/storage-service/rootfs/ /

# /etc/storage-service ownership: sshd-authkeys, not root, since
# identity-provisioner (ST-F-11, KI-01) runs as that account and must be
# able to write here, and authorized-keys-command reads the same files back
# as that same account. Deliberately AFTER the rootfs COPY above, not
# before it: that COPY lands files directly inside /etc/storage-service
# (tailscale-up.sh, trust-mesh-ca.sh, identity-provisioner-ready.sh) and
# was confirmed, by inspecting a real built image, to reset this
# directory's own ownership back to root - chown must be the LAST write to
# this path for the final image to actually have it.
RUN chown sshd-authkeys:sshd-authkeys /etc/storage-service

# No EXPOSE: neither sshd nor storage-service publish a host/ramusb-net
# port anymore (NET-F-01) - both bind exclusively to the Tailscale mesh
# interface address, assigned only at runtime once tailscaled joins (see
# rootfs/etc/s6-overlay/s6-rc.d/tailscale-up/up), so there is no fixed
# value to document via EXPOSE even for documentation purposes.

ENTRYPOINT ["/init"]
