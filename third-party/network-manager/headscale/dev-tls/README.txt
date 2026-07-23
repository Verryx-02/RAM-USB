Dev-only, self-signed TLS certificate/key pair for Headscale, now served
from inside the network-manager Docker Compose service
(deployments/compose/network-manager.yml) rather than the previous,
now-removed standalone network-manager-headscale service. NOT a real
secret - safe to regenerate freely, never used for anything beyond a
local development/test stack.

Regenerate with:

  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout key.dev-only.pem -out cert.dev-only.pem \
    -subj "/CN=network-manager" \
    -addext "subjectAltName=DNS:network-manager,DNS:network-manager-headscale,DNS:localhost,IP:127.0.0.1"

DNS:network-manager-headscale is kept as an extra SAN entry only for
backward compatibility with any not-yet-regenerated deployment still
dialing the old hostname - the container that hostname pointed to no
longer exists. Any existing cert.dev-only.pem/key.dev-only.pem generated
before this session's NM-F-14 container merge lacks the DNS:network-manager
SAN entry Go's TLS hostname verification now needs (every peer's
RAM_USB_TAILSCALE_CONTROL_URL dials "https://network-manager:8080" -
DNS:localhost alone only covers Network-Manager's own co-located mesh
join) - regenerate with the command above before starting the merged
container, or every OTHER service's mesh join fails closed with a TLS
hostname mismatch even though RAM_USB_TAILSCALE_CONTROL_CA_FILE already
trusts the certificate's issuing chain.

Headscale's gRPC coordination API (services/network-manager/internal/
headscale/client.go's Dial) authenticates callers with a bearer API key,
not a client certificate - but the bearer-credential type
(grpc/credentials.PerRPCCredentials) always requires a secure transport,
so Headscale's gRPC listener needs a real TLS certificate even in dev.
Go clients dialing this dev certificate must set
tls.Config.InsecureSkipVerify = true (it is self-signed, not chained to
any trusted root) - a dev-only choice, never appropriate for a real
deployment.
