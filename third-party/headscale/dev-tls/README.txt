Dev-only, self-signed TLS certificate/key pair for the standalone Headscale
deployment's reverse proxy (deployments/compose/headscale.yml,
deployments/docker/headscale/) - this session's architectural change moved
TLS termination from Headscale itself to the reverse proxy in front of it
(see that Dockerfile's own doc comment for the full per-path mTLS design
NM-F-12 needs). NOT a real secret - safe to regenerate freely, never used
for anything beyond a local development/test stack. In production this
same file path is where an operator mounts a real certificate (Let's
Encrypt or otherwise) instead - never this dev-only pair.

Regenerate with:

  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout key.dev-only.pem -out cert.dev-only.pem \
    -subj "/CN=headscale" \
    -addext "subjectAltName=DNS:headscale,DNS:localhost,IP:127.0.0.1"

Two entirely independent things trust this certificate, for two different
reasons:

  1. Every mesh-joined service's own Tailscale coordination-protocol join
     (RAM_USB_TAILSCALE_CONTROL_URL="https://headscale:8080",
     RAM_USB_TAILSCALE_CONTROL_CA_FILE pointing at this cert.dev-only.pem)
     - this is the SAME certificate every one of those service's own
       tailscaled/tsnet control-plane dial trusts, mounted identically
       into each of their own containers.
  2. Network-Manager's own REST admin-API client
     (RAM_USB_NETWORK_MANAGER_HEADSCALE_API_CA_FILE, see
     cmd/network-manager/main.go's buildHeadscaleAPIClient) - a
     deliberately SEPARATE trust decision from (1) even though it happens
     to be the exact same file in this dev/test stack (both are really
     "trust this reverse proxy's public-facing certificate"), because in
     production the two could reasonably diverge (e.g. a real Let's
     Encrypt certificate needs no CA-file trust at all for either use,
     since it already chains to a publicly trusted root).

Neither of the above is RAM-USB's own internal Certificate-Authority
(pkg/pki/CA-F-04) - real end-user Tailscale clients (CL-F-04) must be able
to trust this same reverse-proxy certificate too, and have no reason to
ever trust RAM-USB's private internal CA. See deployments/docker/
headscale/'s own Dockerfile doc comment for the full reasoning.
