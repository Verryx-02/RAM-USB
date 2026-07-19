# syntax=docker/dockerfile:1
#
# Entry-Hub container image. Entry-Hub is a pure Go HTTP server: a public
# HTTPS listener (EH-F-01/EH-F-02/EH-F-03) and an outbound mTLS client to
# Security-Switch (EH-F-07, via pkg/pki's Certificate-Authority
# bootstrap-token flow, PKI-F-01/PKI-F-02, CA-F-04). Unlike
# Storage-Service (deployments/docker/storage-service/Dockerfile), it
# needs no OS-level capability: no sshd, no POSIX user creation, no
# chroot - so it gets a different, more minimal base image, not a copy
# of that pattern.
#
# Base image decision: gcr.io/distroless/static-debian12:nonroot, not
# debian:bookworm-slim. RNF-SEC-03 (defense-in-depth: every layer
# independently re-validates input/minimizes its own exposure) favors
# the smallest attack surface available for the one component in this
# system with a public, internet-facing listener (EH-F-01/02/03):
# distroless ships no shell, no package manager, and no OS beyond the
# minimal files a statically-linked Go binary needs (a CA certificate
# bundle, tzdata, a pre-baked /etc/passwd "nonroot" entry) - there is
# nothing here for a remote attacker to `exec` into even if the Go
# binary itself were somehow compromised. debian:bookworm-slim remains
# the right choice for Storage-Service specifically because that
# service genuinely needs a shell/package-manager-installed sshd,
# useradd/chroot tooling, and s6-overlay's own supervision scripts -
# none of which Entry-Hub has any use for. See the SRS's
# Storage-Service container-architecture [!NOTE] after §4.5 for that
# service's own rationale, and the general container base-image policy
# [!NOTE] after §2.4 for the default this Dockerfile follows.
#
# TLS certificate note (read before running this image):
# Entry-Hub's public listener needs a real TLS certificate/key pair at
# startup - RAM_USB_ENTRY_HUB_TLS_CERT/RAM_USB_ENTRY_HUB_TLS_KEY, two
# file paths loaded via tls.LoadX509KeyPair (see
# services/entry-hub/cmd/entry-hub/main.go's buildServerTLSConfig). In
# production these are issued by the public Let's Encrypt CA - EH-F-01/
# EH-F-02/EH-F-03's literal requirement, so end users never need to
# trust or reach the internal Certificate-Authority - and are supplied
# by the operator via a bind mount at those same two paths; this image
# does not run an ACME client itself.
#
# Let's Encrypt's ACME HTTP-01/DNS-01 challenge requires a real,
# internet-reachable public domain, which does not exist in local dev/
# test. For local `docker compose` testing, generate a dev-only
# self-signed pair instead, following this project's established
# "*.dev-only.*" naming convention (see
# third-party/certificate-authority/config/password.dev-only.txt):
#
#   third-party/entry-hub/generate-dev-cert.sh
#
# then bind-mount the two resulting files
# (third-party/entry-hub/config/server.dev-only.crt/.key) onto the two
# paths above. This dev-only certificate is NEVER valid for production:
# it is self-signed and trusted by nothing but a client explicitly told
# to trust it (or to skip verification) - the real Let's Encrypt flow
# takes over in production, where an operator-managed ACME client
# (outside this image's scope) refreshes the same two file paths
# instead.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/mtls, pkg/pki, pkg/errors, and
# services/entry-hub/... from the module rooted there, not from this
# directory):
#
#   docker build -f deployments/docker/entry-hub/Dockerfile \
#       -t ram-usb/entry-hub .

ARG GO_VERSION=1.26

# ---- build stage: compile the entry-hub binary -------------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary. The distroless/static runtime
# stage below ships no libc/dynamic linker at all, so the binary MUST be
# static, not merely glibc-version-matched the way
# deployments/docker/storage-service/Dockerfile's CGO_ENABLED=0 build
# avoids version drift against its own (dynamically-linked-capable)
# debian:bookworm-slim runtime stage.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/entry-hub \
    ./services/entry-hub/cmd/entry-hub

# ---- runtime stage -------------------------------------------------------
# distroless/static-debian12:nonroot: no shell, no package manager, only
# the minimal runtime files a static Go binary needs (CA certificate
# bundle, tzdata, /etc/passwd/group with a pre-baked "nonroot"
# uid/gid=65532 entry). The ":nonroot" tag variant also pre-sets
# USER nonroot, so no explicit USER instruction is needed below - this
# image never runs as root at any point after the build stage.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/entry-hub /usr/local/bin/entry-hub

# Entry-Hub's own listen port is operator/env configured
# (RAM_USB_ENTRY_HUB_LISTEN_ADDR) and has no single SRS-fixed value to
# document here - 8443 is this Dockerfile's documentation-only default,
# matching the "internal HTTPS on a non-privileged port" convention
# already used by every other service's own Dockerfile/env var pair
# (see e.g. storage-service's EXPOSE 2222 comment for the same idea).
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/entry-hub"]
