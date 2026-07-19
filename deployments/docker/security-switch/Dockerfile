# syntax=docker/dockerfile:1
#
# Security-Switch container image. Unlike Storage-Service (deployments/
# docker/storage-service/Dockerfile), this service is a single, pure Go
# process: one inbound mTLS listener accepting Entry-Hub (SS-F-01) and two
# outbound mTLS clients to Database-Vault (SS-F-04) and Network-Manager
# (SS-F-05/SS-F-09), all three roles sharing one identity obtained at
# startup via pkg/pki's bootstrap-token flow (CA-F-04, PKI-F-01/PKI-F-02 -
# see services/security-switch/cmd/security-switch/main.go's package doc
# comment for the full architecture). There is no sshd, no POSIX user
# management, no chroot, and nothing else that needs a general-purpose
# Linux userland - so this image does NOT copy Storage-Service's
# debian:bookworm-slim + s6-overlay pattern. A distroless runtime base is
# the correct, more minimal choice here (RNF-SEC-03: every layer
# independently re-validates and minimizes its own attack surface;
# RNF-REL-01: an isolated-compromise boundary is stronger when the runtime
# image ships no shell, no package manager, and no other binary an
# attacker who reaches the process could pivot to).
#
# Build context MUST be the repository root (this Dockerfile builds a
# package that imports pkg/mtls, pkg/pki, pkg/errors, pkg/logging, and
# services/security-switch/... from the module rooted there, not from this
# directory):
#
#   docker build -f deployments/docker/security-switch/Dockerfile \
#       -t ram-usb/security-switch .
#
# Runtime configuration is entirely environment-variable driven (see
# main.go's own const block for the full list: RAM_USB_CA_BOOTSTRAP_TOKEN,
# RAM_USB_SECURITY_SWITCH_LISTEN_ADDR, RAM_USB_DATABASE_VAULT_URL,
# RAM_USB_NETWORK_MANAGER_URL, and the optional RAM_USB_MQTT_* metrics
# variables) - none of it is baked into this image.

ARG GO_VERSION=1.26

# ---- build stage: compile a single static binary -----------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary with no libc dependency at all, so
# it can run unmodified on distroless/static-debian12's scratch-like
# runtime (no glibc, no dynamic linker present there whatsoever - unlike
# Storage-Service's CGO_ENABLED=0 choice, which is about avoiding glibc
# *version* drift against a still-glibc-based debian:bookworm-slim runtime,
# this runtime has no libc to link against at all, so CGO_ENABLED=0 here is
# a hard requirement, not a robustness improvement).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/security-switch \
    ./services/security-switch/cmd/security-switch

# ---- runtime stage -------------------------------------------------------
# gcr.io/distroless/static-debian12: no shell, no package manager, no libc
# beyond the minimal static-linking runtime pieces distroless itself needs
# - the smallest attack surface available for a binary with zero OS-level
# requirements. Its :nonroot tag runs as a fixed, dedicated non-root
# UID/GID (65532:65532) by default, so no explicit USER directive is
# needed; unlike Storage-Service, which specifically needs UID 0 plus a
# narrow capability set (CAP_CHOWN/SETUID/SETGID/SYS_CHROOT) to create
# POSIX users and chroot SFTP sessions, Security-Switch never touches the
# filesystem beyond its own binary and never needs any Linux capability at
# all - it can run under the full default `--cap-drop ALL`.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/security-switch /usr/local/bin/security-switch

# distroless/static-debian12:nonroot already runs as UID/GID 65532
# ("nonroot"); no USER directive needed.
ENTRYPOINT ["/usr/local/bin/security-switch"]
