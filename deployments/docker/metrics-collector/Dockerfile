# syntax=docker/dockerfile:1
#
# Metrics-Collector container image. A single Go process: an outbound
# mTLS MQTT subscribe connection (MT-F-01) and an outbound TimescaleDB/
# Postgres write connection (MT-F-03) - no inbound HTTP listener at all
# (see services/metrics-collector/cmd/metrics-collector/main.go's package
# doc comment for why). No sshd, no POSIX users, no chroot, no OS-level
# work of any kind - same shape as Network-Manager's own Dockerfile
# (deployments/docker/network-manager/Dockerfile), whose reasoning for a
# distroless runtime applies identically here.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/metrics and
# services/metrics-collector/... from the module rooted there, not from
# this directory):
#
#   docker build -f deployments/docker/metrics-collector/Dockerfile \
#       -t ram-usb/metrics-collector .

ARG GO_VERSION=1.26

# ---- build stage: compile a fully static binary ------------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary, so the distroless runtime stage
# (no libc package manager, no shell) needs nothing beyond the binary
# itself and the migrations directory copied below.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/metrics-collector \
    ./services/metrics-collector/cmd/metrics-collector

# ---- runtime stage -------------------------------------------------------
# gcr.io/distroless/static-debian12:nonroot: no shell, no package manager,
# no OS userland beyond a minimal libc-free base - this binary makes no
# OS-level calls (no useradd, no chroot, no sshd, no subprocess exec of
# any kind) and needs nothing besides its own static binary, its
# migrations directory (internal/schema.Apply reads these SQL files from
# disk at startup, via RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR - defaults
# to the path this stage copies them to below), and the CA certificates
# bundle distroless images ship by default (used for the outbound
# TimescaleDB connection's TLS trust decisions, if the deployment's
# databaseURL enables TLS - the MQTT broker connection's own trust root is
# supplied separately via RAM_USB_MQTT_CA). Already runs as the image's
# built-in "nonroot" user (uid 65532) - no separate USER directive needed.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/metrics-collector /usr/local/bin/metrics-collector
COPY --from=build /src/services/metrics-collector/migrations /migrations

ENV RAM_USB_METRICS_COLLECTOR_MIGRATIONS_DIR=/migrations

ENTRYPOINT ["/usr/local/bin/metrics-collector"]
