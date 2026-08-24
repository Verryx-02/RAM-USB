package pki

// This file implements CA-F-04's persistence clause: "each service must
// therefore persist the certificate and key it is issued, so that the
// [bootstrap] token is consumed exactly once in the service's lifetime and
// a process or container restart renews from the stored certificate
// instead of re-presenting the token."
//
// Design (load-then-bootstrap-only-if-absent): NewServer/NewClient first
// look for a previously-persisted identity under IdentityDirEnvVar. If one
// exists and is usable, it is handed straight to the vendored SDK's own
// renewal machinery (ca.Client.GetServerTLSConfig/Transport - the exact
// same calls stepca.BootstrapServer/BootstrapClient make internally after
// a token exchange, see bootstrap.go's createBootstrap) - no network call
// to the Certificate-Authority happens at load time, and the bootstrap
// token is never even inspected. Only a genuinely absent identity (first
// run) falls through to a fresh token exchange, whose result is then
// persisted for next time.
//
// What gets persisted, and why each piece is safe to store as plain files:
//   - identity.key: the issued certificate's ECDSA private key (the one
//     sensitive artifact here - RD-02), written with owner-only (0600)
//     permissions into a 0700 directory.
//   - identity.crt: the issued certificate followed by its issuing CA
//     certificate, PEM-encoded - both public information, in the same
//     concatenated-chain layout crypto/tls.LoadX509KeyPair (and this
//     library's own ca.TLSCertificate) already expect.
//   - identity.json: the Certificate-Authority's URL and root certificate
//     SHA-256 fingerprint, both taken verbatim from the bootstrap token's
//     own "aud"/"sha" claims (see parseBootstrapToken) - a fingerprint is
//     not a credential, and pinning it is exactly what ca.Bootstrap/
//     ca.WithRootSHA256 already does with the token's claims on every
//     fresh bootstrap; storing it lets a reload repeat that same pinning
//     without needing the (single-use, by-then-spent) token again.
//
// Fail-closed (RD-04): a stored identity that exists but cannot be used
// (unreadable, corrupt, expired, or otherwise malformed) is a hard error.
// It is never treated as "absent" and never silently falls back to
// consuming the bootstrap token - that would mask exactly the kind of
// failure this persistence mechanism exists to make visible.
import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smallstep/certificates/api"
	stepca "github.com/smallstep/certificates/ca"
	"go.step.sm/crypto/jose"
)

// IdentityDirEnvVar names the environment variable holding the directory
// this package persists its bootstrapped mTLS identity under (CA-F-04).
// This name is this package's own judgment call (the SRS specifies only
// that the identity must be persisted, not a variable name or path),
// chosen to follow the same RAM_USB_* convention as BootstrapTokenEnvVar.
const IdentityDirEnvVar = "RAM_USB_PKI_IDENTITY_DIR"

// defaultIdentityDir is used whenever IdentityDirEnvVar is unset. Every
// RAM-USB service container is expected to mount a durable volume at this
// path (see deployments/compose/*.yml) so the identity survives a
// container recreate, not just a process restart within the same
// container filesystem layer.
const defaultIdentityDir = "/var/lib/ram-usb/pki-identity"

const (
	identityKeyFile  = "identity.key"
	identityCertFile = "identity.crt"
	identityMetaFile = "identity.json"
)

// identityDir resolves the directory this process persists its identity
// under.
func identityDir() string {
	if dir := os.Getenv(IdentityDirEnvVar); dir != "" {
		return dir
	}
	return defaultIdentityDir
}

// errIdentityAbsent signals a genuine first run: no identity is stored yet,
// so the caller must fall through to a fresh bootstrap-token exchange. This
// is the ONLY condition under which that fallback is allowed - any other
// error loading a stored identity must propagate as a hard failure (RD-04).
var errIdentityAbsent = errors.New("pki: no stored identity found")

// identityMeta is the on-disk (identity.json) shape of the non-secret
// pinning information a reload needs to reach the Certificate-Authority
// again without the original bootstrap token - see this file's package
// doc comment.
type identityMeta struct {
	CAURL      string `json:"ca_url"`
	RootSHA256 string `json:"root_sha256"`
}

// resolvedIdentity is everything NewServer/NewClient need to hand to
// ca.Client.GetServerTLSConfig/Transport, regardless of whether it came
// from a fresh bootstrap-token exchange or a stored identity reload.
type resolvedIdentity struct {
	caURL      string
	rootSHA256 string
	sign       *api.SignResponse
	pk         crypto.PrivateKey
}

// establishIdentity implements this file's load-then-bootstrap-only-if-
// absent design: it returns the stored identity if one is usable, and
// otherwise performs a fresh bootstrap-token exchange (consuming token) and
// persists the result for next time.
func establishIdentity(token, dir string) (*resolvedIdentity, error) {
	stored, err := loadStoredIdentity(dir)
	switch {
	case err == nil:
		return stored, nil
	case errors.Is(err, errIdentityAbsent):
		return bootstrapNewIdentity(token, dir)
	default:
		// A stored identity exists but is unusable - fail closed (RD-04)
		// rather than silently burning the bootstrap token, which would
		// mask this failure instead of surfacing it.
		return nil, err
	}
}

// loadStoredIdentity reads a previously-persisted identity from dir. It
// returns errIdentityAbsent (wrapped) when no identity has been stored
// yet, and any other error when one exists but cannot be used - callers
// must not treat the latter as equivalent to absence (see this file's
// package doc comment on fail-closed behavior).
func loadStoredIdentity(dir string) (*resolvedIdentity, error) {
	certPath := filepath.Join(dir, identityCertFile)
	keyPath := filepath.Join(dir, identityKeyFile)
	metaPath := filepath.Join(dir, identityMetaFile)

	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return nil, errIdentityAbsent
		}
		return nil, fmt.Errorf("pki: stat stored identity certificate: %w", err)
	}

	//nolint:gosec // G304: metaPath is derived from dir, this process's own
	// configured identity directory (IdentityDirEnvVar or the fixed
	// default), never externally-supplied request input.
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("pki: stored identity metadata unreadable: %w", err)
	}
	var meta identityMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("pki: stored identity metadata corrupt: %w", err)
	}
	if meta.CAURL == "" || meta.RootSHA256 == "" {
		return nil, errors.New("pki: stored identity metadata incomplete: ca_url and root_sha256 are both required")
	}

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("pki: stored identity certificate/key unusable: %w", err)
	}
	if len(tlsCert.Certificate) < 2 {
		return nil, errors.New("pki: stored identity certificate chain incomplete: want leaf and issuing CA certificate")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("pki: stored identity leaf certificate unparsable: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("pki: stored identity certificate not currently valid (notBefore=%s, notAfter=%s, now=%s)",
			leaf.NotBefore, leaf.NotAfter, now)
	}

	issuer, err := x509.ParseCertificate(tlsCert.Certificate[1])
	if err != nil {
		return nil, fmt.Errorf("pki: stored identity issuing certificate unparsable: %w", err)
	}

	return &resolvedIdentity{
		caURL:      meta.CAURL,
		rootSHA256: meta.RootSHA256,
		sign: &api.SignResponse{
			ServerPEM: api.NewCertificate(leaf),
			CaPEM:     api.NewCertificate(issuer),
		},
		pk: tlsCert.PrivateKey,
	}, nil
}

// bootstrapNewIdentity performs the one-time exchange of token for an
// initial certificate (CA-F-04) and persists the result under dir. This is
// the ONLY code path in this package that ever consumes a bootstrap token.
//
// It replicates github.com/smallstep/certificates/ca@v0.30.2's own
// createBootstrap (ca/bootstrap.go, unexported) using only that package's
// exported surface (ca.NewClient, ca.WithRootSHA256, ca.CreateSignRequest,
// Client.Version, Client.Sign) so the CA URL and root fingerprint used to
// build the *ca.Client are available to persist afterward - values
// ca.Bootstrap/ca.BootstrapServer/ca.BootstrapClient parse internally but
// never return to the caller.
func bootstrapNewIdentity(token, dir string) (*resolvedIdentity, error) {
	caURL, rootSHA256, err := parseBootstrapToken(token)
	if err != nil {
		return nil, err
	}

	client, err := stepca.NewClient(caURL, stepca.WithRootSHA256(rootSHA256))
	if err != nil {
		return nil, err
	}
	if _, err := client.Version(); err != nil {
		return nil, err
	}

	req, pk, err := stepca.CreateSignRequest(token)
	if err != nil {
		return nil, err
	}
	sign, err := client.Sign(req)
	if err != nil {
		return nil, err
	}

	id := &resolvedIdentity{caURL: caURL, rootSHA256: rootSHA256, sign: sign, pk: pk}
	if err := saveStoredIdentity(dir, id); err != nil {
		return nil, fmt.Errorf("pki: persist bootstrapped identity: %w", err)
	}
	return id, nil
}

// parseBootstrapToken extracts the Certificate-Authority URL and root
// certificate SHA-256 fingerprint from token, applying the same validation
// ca.Bootstrap does (github.com/smallstep/certificates/ca@v0.30.2's
// ca/bootstrap.go) so a malformed token is rejected identically, with no
// network call made. bootstrapTokenClaims (rootca.go) already mirrors that
// library's own unexported claims shape, so it is reused here rather than
// duplicated a second time.
func parseBootstrapToken(token string) (caURL, rootSHA256 string, err error) {
	tok, err := jose.ParseSigned(token)
	if err != nil {
		return "", "", fmt.Errorf("pki: parsing bootstrap token: %w", err)
	}
	var claims bootstrapTokenClaims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", "", fmt.Errorf("pki: parsing bootstrap token: %w", err)
	}

	switch {
	case claims.SHA == "":
		return "", "", errors.New("pki: invalid bootstrap token: sha claim is not present")
	case len(claims.Audience) == 0:
		return "", "", errors.New("pki: invalid bootstrap token: aud claim is not present")
	case !strings.HasPrefix(strings.ToLower(claims.Audience[0]), "http"):
		return "", "", errors.New("pki: invalid bootstrap token: aud claim is not a url")
	}

	return claims.Audience[0], claims.SHA, nil
}

// saveStoredIdentity persists id under dir so a future process start can
// reload it via loadStoredIdentity instead of consuming another bootstrap
// token.
func saveStoredIdentity(dir string, id *resolvedIdentity) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}

	chainPEM := encodeCertChainPEM(id.sign.ServerPEM.Certificate, id.sign.CaPEM.Certificate)
	keyPEM, err := encodeKeyPEM(id.pk)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(identityMeta{CAURL: id.caURL, RootSHA256: id.rootSHA256})
	if err != nil {
		return fmt.Errorf("marshal identity metadata: %w", err)
	}

	// The private key is the one genuinely sensitive artifact here
	// (RD-02) - written first, owner-only (0600). The certificate and
	// metadata are public information (the issued certificate, the CA's
	// URL, and its root fingerprint) but are written 0600 too for
	// simplicity, since the containing directory is already 0700
	// (owner-only).
	if err := os.WriteFile(filepath.Join(dir, identityKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write identity key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, identityCertFile), chainPEM, 0o600); err != nil {
		return fmt.Errorf("write identity certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, identityMetaFile), metaJSON, 0o600); err != nil {
		return fmt.Errorf("write identity metadata: %w", err)
	}
	return nil
}

// encodeCertChainPEM PEM-encodes certs in order, skipping any nil entry.
func encodeCertChainPEM(certs ...*x509.Certificate) []byte {
	var buf []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return buf
}

// encodeKeyPEM PEM-encodes pk in PKCS#8 form, the same encoding
// crypto/tls.X509KeyPair's parser (and this library's own ca/identity
// package) accepts regardless of the underlying key algorithm.
func encodeKeyPEM(pk crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("marshal identity private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// newStepClientFor reconstructs a *ca.Client pinned to id's CA URL and root
// fingerprint - the same pinning ca.Bootstrap performs from a token's
// claims, replayed here from the persisted (or just-bootstrapped) values
// instead. No token is involved.
func newStepClientFor(id *resolvedIdentity) (*stepca.Client, error) {
	return stepca.NewClient(id.caURL, stepca.WithRootSHA256(id.rootSHA256))
}

// rootsOptionsFor returns the TLSOptions NewServer/NewClient must apply on
// top of forceTLS13, mirroring ca.BootstrapServer/ca.BootstrapClient's own
// conditional root-fetch (ca/bootstrap.go): the roots-refresh request is
// only supported when the provisioner does not require client
// authentication for it.
func rootsOptionsFor(version *api.VersionResponse, forServer bool) []stepca.TLSOption {
	options := []stepca.TLSOption{forceTLS13}
	if version.RequireClientAuthentication {
		return options
	}
	if forServer {
		return append(options, stepca.AddRootsToCAs())
	}
	return append(options, stepca.AddRootsToRootCAs())
}
