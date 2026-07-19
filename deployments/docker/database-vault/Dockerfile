# syntax=docker/dockerfile:1
#
# Database-Vault container image. A pure Go process (DV-F-01..DV-F-20):
# two mTLS HTTP listeners (register/login accepting Security-Switch, and
# ST-F-11's public-key lookup accepting Storage-Service, both sharing one
# CA-bootstrapped identity via pkg/pki, CA-F-04), an outbound mTLS client
# to Storage-Service (DV-F-09), a Postgres connection (DV-F-08), and an
# automatic schema-migration step at startup (internal/schema, applied
# before this process starts serving). Unlike Storage-Service, this
# service needs no OS-level facilities (no sshd, no useradd/chroot, no
# process supervisor) - see the container base-image policy [!NOTE] after
# SRS §2.4 for why this image's base differs from Storage-Service's
# debian:bookworm-slim one.
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
# optional RAM_USB_DATABASE_VAULT_MIGRATIONS_DIR / RAM_USB_MQTT_* group) -
# wired for real in docker-compose.dev.yml, a separate task. No cert/key
# files are baked into or mounted onto this image: this service's TLS
# identity is obtained at startup from the Certificate-Authority via
# pkg/pki's bootstrap-token flow (CA-F-04, PKI-F-01), not from disk.

ARG GO_VERSION=1.26

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
# gcr.io/distroless/static-debian12:nonroot (RNF-SEC-03: minimal attack
# surface - no shell, no package manager, no libc beyond the few shared
# libraries static Go binaries don't need anyway) rather than
# debian:bookworm-slim: this service has no sshd/useradd/chroot dependency
# the way Storage-Service does (see SRS §4.5's [!NOTE]), so there is no
# reason to carry a full Debian userland here. The ":nonroot" tag already
# runs as a dedicated unprivileged "nonroot" account (UID/GID 65532),
# confirmed via `docker inspect` this session - no separate `useradd` step
# is possible (no shell) or needed.
FROM gcr.io/distroless/static-debian12:nonroot

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
# main.go's constant against this image's contents.
WORKDIR /app

COPY --from=build /out/database-vault /app/database-vault
COPY services/database-vault/migrations /app/services/database-vault/migrations

USER nonroot:nonroot

ENTRYPOINT ["/app/database-vault"]
