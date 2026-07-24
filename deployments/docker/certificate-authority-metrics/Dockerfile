# syntax=docker/dockerfile:1
#
# Certificate-Authority metrics sidecar (CA-F-03). A pure Go process: no
# OS-level capability beyond reading a bind-mounted log file and an
# outbound mTLS/MQTT connection - same reasoning as
# deployments/docker/entry-hub/Dockerfile for its own distroless base
# image choice (RNF-SEC-03: smallest attack surface for the one
# component with no OS-level requirement). See
# services/certificate-authority/cmd/metrics-sidecar/main.go's own package
# doc comment for why this is a separate process from step-ca itself,
# and deployments/compose/certificate-authority.yml for how it obtains
# step-ca's own access log.
#
# Build context MUST be the repository root (this Dockerfile builds
# packages that import pkg/mesh, pkg/metrics, pkg/pki, and
# services/certificate-authority/... from the module rooted there):
#
#   docker build -f deployments/docker/certificate-authority-metrics/Dockerfile \
#       -t ram-usb/certificate-authority-metrics .

ARG GO_VERSION=1.26

# ---- build stage: compile the metrics-sidecar binary --------------------
FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: a fully static binary - the distroless/static runtime
# stage below ships no libc/dynamic linker at all.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/certificate-authority-metrics \
    ./services/certificate-authority/cmd/metrics-sidecar

# pkg/mesh's tsnet state directory (RAM_USB_CERTIFICATE_AUTHORITY_METRICS_MESH_DIR,
# mounted onto /var/lib/tsnet below as a named volume) needs to be owned
# by the distroless runtime stage's unprivileged "nonroot" account
# (UID/GID 65532) BEFORE that volume is ever created - see
# deployments/docker/entry-hub/Dockerfile's own identical comment for the
# full reasoning (a brand-new named volume mounts root-owned by default,
# leaving tsnet unable to write its own state as UID 65532 otherwise).
RUN mkdir -p /tsnet-seed && chown 65532:65532 /tsnet-seed

# ---- runtime stage --------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/certificate-authority-metrics /usr/local/bin/certificate-authority-metrics
COPY --from=build --chown=65532:65532 /tsnet-seed /var/lib/tsnet

ENTRYPOINT ["/usr/local/bin/certificate-authority-metrics"]
