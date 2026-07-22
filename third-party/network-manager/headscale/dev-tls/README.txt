Dev-only, self-signed TLS certificate/key pair for the
network-manager-headscale Docker Compose service
(deployments/compose/headscale.yml). NOT a real secret - safe to regenerate freely,
never used for anything beyond a local development/test stack.

Regenerate with:

  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout key.dev-only.pem -out cert.dev-only.pem \
    -subj "/CN=network-manager-headscale" \
    -addext "subjectAltName=DNS:network-manager-headscale,DNS:localhost,IP:127.0.0.1"

Headscale's gRPC coordination API (services/network-manager/internal/
headscale/client.go's Dial) authenticates callers with a bearer API key,
not a client certificate - but the bearer-credential type
(grpc/credentials.PerRPCCredentials) always requires a secure transport,
so Headscale's gRPC listener needs a real TLS certificate even in dev.
Go clients dialing this dev certificate must set
tls.Config.InsecureSkipVerify = true (it is self-signed, not chained to
any trusted root) - a dev-only choice, never appropriate for a real
deployment.
