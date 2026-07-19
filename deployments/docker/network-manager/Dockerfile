# syntax=docker/dockerfile:1
#
# Network-Manager container image. A single Go process: one inbound mTLS
# HTTP listener (NM-F-03, accepts only Security-Switch and, via CA-F-04's
# bootstrap-token flow at startup, the Certificate-Authority) plus an
# outbound gRPC client connection to Headscale (a separate third-party
# container, bearer-API-key authenticated - not part of pkg/pki/mTLS, see
# services/network-manager/cmd/network-manager/main.go's package doc
# comment). No sshd, no POSIX users, no chroot, no OS-level work of any
# kind - unlike Storage-Service (deployments/docker/storage-service/
# Dockerfile), which genuinely needs a full Debian userland for exactly
# those things. A distroless runtime is the correct, narrower choice here:
# smaller attack surface (RNF-SEC-03, defense-in-depth), no package
# manager/shell/coreutils to harden or patch, consistent with this binary
# having nothing to shell out to.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/mtls, pkg/pki, and
# services/network-manager/... from the module rooted there, not from
# this directory):
#
#   docker build -f deployments/docker/network-manager/Dockerfile \
#       -t ram-usb/network-manager .

ARG GO_VERSION=1.26

# ---- build stage: compile a fully static binary ------------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary, so the distroless runtime stage
# (no libc package manager, no shell) needs nothing beyond the binary
# itself - same reasoning as Storage-Service's own build stage, restated
# here because that Dockerfile's comment is specific to glibc-version
# coupling with debian:bookworm-slim, which does not apply to this image's
# runtime stage at all.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/network-manager \
    ./services/network-manager/cmd/network-manager

# ---- runtime stage -------------------------------------------------------
# gcr.io/distroless/static-debian12:nonroot: no shell, no package manager,
# no OS userland beyond a minimal libc-free base - appropriate because
# this binary makes no OS-level calls (no useradd, no chroot, no sshd, no
# subprocess exec of any kind) and needs nothing besides its own static
# binary and the CA certificates bundle distroless images ship by default
# (used only for internal/headscale's own gRPC TLS trust decisions, not
# for the CA-F-04 bootstrap flow, which supplies its own trust root at
# runtime via pkg/pki). Already runs as the image's built-in "nonroot"
# user (uid 65532) - no separate USER directive needed.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/network-manager /usr/local/bin/network-manager

# NM-F-03's mTLS listen port is operator/env configured
# (RAM_USB_NETWORK_MANAGER_LISTEN_ADDR) and has no single fixed value to
# document here - same convention as Storage-Service's own Dockerfile for
# its mTLS listener.
ENTRYPOINT ["/usr/local/bin/network-manager"]
