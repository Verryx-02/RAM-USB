# syntax=docker/dockerfile:1
#
# Certificate-Authority container image. Since docs/Known_Issues.md's
# KI-28, this container now bundles TWO processes, s6-supervised together:
# the official smallstep/step-ca binary (CA-F-01/CA-F-02, "provided by the
# underlying product" per the SRS's own note) AND CA-F-03's metrics
# sidecar (services/certificate-authority/cmd/metrics-sidecar), previously
# a separate container/Compose project
# (deployments/compose/certificate-authority-metrics.yml, now removed).
#
# Why merge them: the metrics sidecar's own CA-bootstrap-token exchange
# uses a hard, non-interceptable dial path inside
# github.com/smallstep/certificates (see .claude/agent-memory/code-agent/
# pkg-pki-dialer-routing.md) - the same gap KI-27 found for Entry-Hub.
# Co-locating this process inside step-ca's own container removes the
# problem at its root instead of routing around it: the CA-bootstrap-token
# exchange becomes a purely local call (https://localhost:9000, no network
# hop at all), and the metrics sidecar's own MQTT publish rides the SAME
# real, OS-level `tailscaled` sidecar (`certificate-authority-mesh`,
# deployments/compose/certificate-authority.yml, sharing this container's
# network namespace) step-ca's own inbound mesh reachability (NM-F-04)
# already depends on - no separate `pkg/mesh` identity, no separate
# Tailscale pre-auth key, for this process anymore. See
# services/certificate-authority/cmd/metrics-sidecar/main.go's own package
# doc comment for the full reasoning, and docs/Known_Issues.md's KI-28 for
# the live verification.
#
# Same "build FROM the official upstream image itself rather than
# hand-copying binaries/libs onto a minimal base" pattern already used for
# Database-Vault+Postgres, Network-Manager+Headscale, and
# Metrics-Collector+TimescaleDB (see deployments/docker/database-vault/
# Dockerfile's own comment) - s6-overlay and the metrics-sidecar Go binary
# are layered on top of smallstep/step-ca:latest, unmodified otherwise.
#
# Build context MUST be the repository root (this Dockerfile builds a
# package that imports pkg/metrics, pkg/pki, and
# services/certificate-authority/... from the module rooted there):
#
#   docker build -f deployments/docker/certificate-authority/Dockerfile \
#       -t ram-usb/certificate-authority .

ARG GO_VERSION=1.26
ARG S6_OVERLAY_VERSION=3.2.3.2

# ---- build stage: compile the metrics-sidecar binary ---------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary - no libc dependency added to the
# Alpine-based runtime stage below.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/certificate-authority-metrics \
    ./services/certificate-authority/cmd/metrics-sidecar

# ---- runtime stage --------------------------------------------------------
# smallstep/step-ca (Alpine-based, confirmed live: /etc/os-release reports
# Alpine, /sbin/apk present, no apt-get) rather than a distroless/minimal
# base - this image now has a genuine OS-level requirement (multi-process
# supervision via s6-overlay) a distroless image cannot satisfy, per the
# container base-image policy [!NOTE] after SRS §2.4. The image's own
# default USER (step, uid 1000) is overridden back to root below: s6-
# overlay's own /init supervisor needs root (same as every other
# s6-overlay precedent in this project - see .claude/agent-memory/code-
# agent/s6-overlay.md, "all four precedents run entirely as root"); step-ca
# itself still runs as the unprivileged "step" user via s6-setuidgid in its
# own longrun's run script, matching /home/step's existing ownership.
FROM smallstep/step-ca:latest
ARG S6_OVERLAY_VERSION
ARG TARGETARCH
USER root

# xz: extracts the s6-overlay release tarballs below (curl and
# ca-certificates are already present in this base image, confirmed live).
RUN apk add --no-cache xz

# s6-overlay: process supervision for the step-ca/certificate-authority-
# metrics longruns plus the step-ca-ready/mint-metrics-token/
# mqtt-broker-ready oneshots (see rootfs/etc/s6-overlay/s6-rc.d/) -
# identical mechanism to deployments/docker/metrics-collector/Dockerfile's
# own s6-overlay install (Alpine arch mapping: amd64 -> x86_64, arm64 ->
# aarch64).
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

# The access-log directory step-ca's own tee'd command (step-ca longrun's
# run script) writes into and the metrics sidecar reads from - both now
# the SAME local filesystem path in the SAME container, no cross-container
# shared volume needed anymore (KI-28). Owned by uid/gid 1000 (the "step"
# user step-ca itself runs as) so its own tee can write here without a
# separate chown init step - a named volume mounted onto this path later
# inherits this ownership from the image (Docker copies a volume's mount
# point's existing content/ownership into a brand-new named volume on
# first mount).
RUN mkdir -p /var/log/certificate-authority && \
    chown 1000:1000 /var/log/certificate-authority && \
    chmod 0755 /var/log/certificate-authority

COPY --from=build /out/certificate-authority-metrics /usr/local/bin/certificate-authority-metrics
RUN chmod 0755 /usr/local/bin/certificate-authority-metrics

# s6-rc.d service definitions (step-ca longrun wrapping the image's own
# /entrypoint.sh, step-ca-ready/mint-metrics-token/mqtt-broker-ready
# oneshots, certificate-authority-metrics longrun) plus their user-bundle
# membership files, and the shell scripts they hand off to (with-contenv/
# execline restrictions - see .claude/agent-memory/code-agent/s6-overlay.md
# for why oneshot up files can't hold real shell logic directly).
COPY deployments/docker/certificate-authority/rootfs/ /

# No EXPOSE: this image never publishes step-ca's own port directly - the
# certificate-authority.yml Compose service's own `ports:`/`networks:`
# entries (unchanged by this consolidation) still control that.

ENTRYPOINT ["/init"]
