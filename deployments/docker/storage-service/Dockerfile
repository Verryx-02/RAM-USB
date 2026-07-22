# syntax=docker/dockerfile:1
#
# Storage-Service container image. Two independent long-lived processes -
# a hardened sshd (ST-F-03/04/07/08/09) and this repo's storage-service Go
# mTLS HTTP server (ST-F-01/06/10) - are supervised by s6-overlay on a
# debian:bookworm-slim base, per the SRS 4.5 [!NOTE] right after Storage-
# Service's directory-structure diagram. ST-F-11's authorized-keys-command
# binary is installed alongside but is NOT a supervised service: sshd
# invokes it once per SFTP connection attempt, via the AuthorizedKeysCommand
# directive in sshd_config (see that file for the full directive set).
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
#       --cap-add SYS_CHROOT
#
# This is why sshd listens on port 2222, not 22: CAP_NET_BIND_SERVICE is
# deliberately not in that set, and without it even UID 0 cannot bind a
# port below 1024 inside the container (verified empirically this session -
# see the code-agent report/memory for the observed failure on :22 and
# success on :2222 under this exact capability set).

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2

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

# ---- runtime stage ------------------------------------------------------
FROM debian:bookworm-slim
ARG S6_OVERLAY_VERSION
ARG TARGETARCH

# openssh-server: sshd + ssh-keygen (ST-F-03/04/07/08/09).
# passwd: useradd/groupadd, the tools services/storage-service/internal/posixuser
# shells out to (ST-F-06) - already Debian-"essential" in most images, listed
# explicitly so this Dockerfile does not depend on that remaining true.
# xz-utils: needed to extract the .tar.xz s6-overlay release tarballs below.
# curl, ca-certificates: fetch those tarballs over HTTPS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    passwd \
    xz-utils \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# s6-overlay: process supervision for the two longruns (sshd, storage-service)
# plus the sshd-hostkeys oneshot. TARGETARCH is set automatically by
# BuildKit to the image's target platform (amd64/arm64); mapped here to
# s6-overlay's own release-asset architecture names (x86_64/aarch64).
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

# AuthorizedKeysCommand runs as this dedicated, unprivileged system account
# (per this session's task instructions), with no other role on the
# container - sshd_config's AuthorizedKeysCommandUser directive names it.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin sshd-authkeys

# /storage: root of all users (SRS 4.5's directory-structure diagram).
# /etc/storage-service: holds authorized-keys-command.conf, per
# services/storage-service/cmd/authorized-keys-command/main.go's fixed
# configPath contract - its real contents are supplied by the deployment/
# docker-compose task, not this Dockerfile.
RUN mkdir -p /storage /etc/storage-service

COPY --from=build /out/storage-service /usr/local/bin/storage-service
COPY --from=build /out/authorized-keys-command /usr/local/bin/authorized-keys-command
# sshd(8)/sshd_config(5) refuses an AuthorizedKeysCommand binary that is
# group- or world-writable. COPY already leaves these root-owned; chmod
# 0755 makes the "not group/world-writable" property explicit rather than
# relying on COPY's default.
RUN chmod 0755 /usr/local/bin/storage-service /usr/local/bin/authorized-keys-command

COPY deployments/docker/storage-service/sshd_config /etc/ssh/sshd_config

# s6-rc.d service definitions (sshd-hostkeys oneshot, sshd and
# storage-service longruns) plus their user-bundle membership files - see
# this directory's own files for the full layout s6-overlay's README
# documents.
COPY deployments/docker/storage-service/rootfs/ /

# sshd's own port; storage-service's mTLS listen port is operator/env
# configured (RAM_USB_STORAGE_SERVICE_LISTEN_ADDR) and has no single fixed
# value to document here.
EXPOSE 2222

ENTRYPOINT ["/init"]
