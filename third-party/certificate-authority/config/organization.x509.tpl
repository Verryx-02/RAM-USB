{{/*
  Custom x509 leaf-certificate template for the "admin" JWK provisioner
  (CA-F-04's bootstrap-token provisioner), installed via
  third-party/certificate-authority/apply-organization-template.sh.

  step-ca's DEFAULT x509 template only sets Subject.CommonName and SANs
  from the bootstrap token's subject/sans claims - it never sets
  Subject.Organization. Confirmed empirically this session: minting a
  token and inspecting the resulting certificate before this template
  existed produced "Subject: CN=<subject>" with no "O=" component at all.

  PKI-F-02 requires every service to verify the peer certificate's
  organization field - pkg/mtls's verifyOrganization (handshake-level,
  ServerConfig/ClientConfig) and RequireOrganization/WrapRoundTripper
  (HTTP-request-level, for services built on pkg/pki) both read
  leaf.Subject.Organization. Without this template, that field is always
  empty on every certificate this CA issues, so it can never match any
  allowedOrganization - PKI-F-02 would be unenforceable end-to-end.

  This template makes Subject.Organization mirror Subject.CommonName, so
  minting a bootstrap token with the desired organization string as its
  subject (e.g. `step ca token SecuritySwitch`) produces a certificate
  with Subject: O=SecuritySwitch,CN=SecuritySwitch - exactly what every
  RAM-USB service's per-organization check expects.
*/}}
{
	"subject": {
		"commonName": {{ toJson .Subject.CommonName }},
		"organization": [{{ toJson .Subject.CommonName }}]
	},
	"sans": {{ toJson .SANs }},
	{{- if typeIs "*rsa.PublicKey" .Insecure.CR.PublicKey }}
	"keyUsage": ["keyEncipherment", "digitalSignature"],
	{{- else }}
	"keyUsage": ["digitalSignature"],
	{{- end }}
	"extKeyUsage": ["serverAuth", "clientAuth"]
}
