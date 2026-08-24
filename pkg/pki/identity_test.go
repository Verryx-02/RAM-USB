package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/certificates/api"
)

// selfSignedCert generates a throwaway, self-signed leaf certificate with
// the given validity window, and its matching private key. Used to build a
// stand-in stored identity without a real Certificate-Authority: none of
// loadStoredIdentity's checks require chain validation against a real
// trust root (that only happens later, during a real TLS handshake), only
// that the two PEM-encoded certificates and the key are individually
// well-formed and that the leaf's own validity window is honored.
func selfSignedCert(t *testing.T, commonName string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	return cert, key
}

// writeFakeIdentity persists a syntactically valid stored identity (leaf +
// issuing certificate, key, metadata) under dir, with the leaf's validity
// window controlled by the caller - this is the same on-disk shape
// saveStoredIdentity produces, built directly here so tests don't need a
// real Certificate-Authority to exercise loadStoredIdentity/
// establishIdentity's reload path.
func writeFakeIdentity(t *testing.T, dir string, notBefore, notAfter time.Time) {
	t.Helper()

	leaf, leafKey := selfSignedCert(t, "pki-test-leaf", notBefore, notAfter)
	issuer, _ := selfSignedCert(t, "pki-test-issuing-ca", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	id := &resolvedIdentity{
		caURL:      "https://ca.pki-test.invalid",
		rootSHA256: "deadbeef",
		sign: &api.SignResponse{
			ServerPEM: api.NewCertificate(leaf),
			CaPEM:     api.NewCertificate(issuer),
		},
		pk: leafKey,
	}
	if err := saveStoredIdentity(dir, id); err != nil {
		t.Fatalf("saveStoredIdentity() error = %v", err)
	}
}

// Requirement: CA-F-04
//
// A genuinely empty identity directory (first run) must be reported as
// errIdentityAbsent, not any other error - establishIdentity relies on this
// exact distinction to decide whether falling through to the bootstrap
// token is allowed.
func TestLoadStoredIdentity_Absent(t *testing.T) {
	dir := t.TempDir()

	_, err := loadStoredIdentity(filepath.Join(dir, "does-not-exist"))
	if !errors.Is(err, errIdentityAbsent) {
		t.Fatalf("loadStoredIdentity() error = %v, want errIdentityAbsent", err)
	}
}

// Requirement: CA-F-04
//
// Second run: a valid stored identity is used as-is, and the bootstrap
// token is never even inspected - establishIdentity must not attempt to
// parse or otherwise consult a malformed/garbage token when a usable
// identity is already on disk (the single-use token must never be touched
// on a restart).
func TestEstablishIdentity_ValidStoredIdentity_TokenNeverConsulted(t *testing.T) {
	dir := t.TempDir()
	writeFakeIdentity(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	id, err := establishIdentity("not-a-real-token-and-must-never-be-parsed", dir)
	if err != nil {
		t.Fatalf("establishIdentity() error = %v, want nil", err)
	}
	if id.caURL != "https://ca.pki-test.invalid" {
		t.Fatalf("establishIdentity() caURL = %q, want %q", id.caURL, "https://ca.pki-test.invalid")
	}
	if id.rootSHA256 != "deadbeef" {
		t.Fatalf("establishIdentity() rootSHA256 = %q, want %q", id.rootSHA256, "deadbeef")
	}
}

// Requirement: CA-F-04
//
// First run: with no stored identity, establishIdentity must fall through
// to a bootstrap-token exchange - proven here by observing that a
// malformed token now DOES produce a token-parsing error (as opposed to
// the previous test, where the same malformed token was never touched).
func TestEstablishIdentity_NoStoredIdentity_FallsThroughToToken(t *testing.T) {
	dir := t.TempDir()

	_, err := establishIdentity("not-a-real-token", filepath.Join(dir, "identity"))
	if err == nil {
		t.Fatal("establishIdentity() error = nil, want a bootstrap-token parsing error")
	}
}

// Requirement: CA-F-04
//
// A stored identity that exists but is unusable (here: the certificate is
// expired) must fail closed (RD-04) - establishIdentity must return an
// error and must NOT fall back to consuming the bootstrap token, which
// would silently mask the corruption instead of surfacing it.
func TestEstablishIdentity_ExpiredStoredIdentity_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeFakeIdentity(t, dir, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))

	_, err := establishIdentity("not-a-real-token-and-must-never-be-parsed", dir)
	if err == nil {
		t.Fatal("establishIdentity() error = nil, want an error for an expired stored identity")
	}
	if errors.Is(err, errIdentityAbsent) {
		t.Fatal("establishIdentity() treated an expired stored identity as absent - it must fail closed instead")
	}
}

// Requirement: CA-F-04
//
// A stored identity missing its key file (certificate present, key gone)
// must fail closed the same way an expired certificate does - a corrupt or
// incomplete identity is never treated as "absent" and must never trigger
// a fresh bootstrap.
func TestEstablishIdentity_MissingKeyFile_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeFakeIdentity(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	if err := os.Remove(filepath.Join(dir, identityKeyFile)); err != nil {
		t.Fatalf("os.Remove(identity.key) error = %v", err)
	}

	_, err := establishIdentity("not-a-real-token-and-must-never-be-parsed", dir)
	if err == nil {
		t.Fatal("establishIdentity() error = nil, want an error for a stored identity missing its key file")
	}
	if errors.Is(err, errIdentityAbsent) {
		t.Fatal("establishIdentity() treated a stored identity missing its key file as absent - it must fail closed instead")
	}
}

// Requirement: CA-F-04
//
// A stored identity with corrupt metadata (unparsable identity.json) must
// also fail closed rather than being treated as absent.
func TestEstablishIdentity_CorruptMetadata_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeFakeIdentity(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	if err := os.WriteFile(filepath.Join(dir, identityMetaFile), []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(identity.json) error = %v", err)
	}

	_, err := establishIdentity("not-a-real-token-and-must-never-be-parsed", dir)
	if err == nil {
		t.Fatal("establishIdentity() error = nil, want an error for corrupt stored identity metadata")
	}
	if errors.Is(err, errIdentityAbsent) {
		t.Fatal("establishIdentity() treated corrupt stored identity metadata as absent - it must fail closed instead")
	}
}

// Requirement: CA-F-04
//
// saveStoredIdentity must write the private key with owner-only (0600)
// permissions (RD-02) - the one genuinely sensitive artifact this package
// persists.
func TestSaveStoredIdentity_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	writeFakeIdentity(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	info, err := os.Stat(filepath.Join(dir, identityKeyFile))
	if err != nil {
		t.Fatalf("os.Stat(identity.key) error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity.key permissions = %o, want %o", perm, 0o600)
	}
}

// Requirement: CA-F-04
//
// identityDir must default to defaultIdentityDir when IdentityDirEnvVar is
// unset, and honor the environment variable when it is set.
func TestIdentityDir(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		prev, had := os.LookupEnv(IdentityDirEnvVar)
		if err := os.Unsetenv(IdentityDirEnvVar); err != nil {
			t.Fatalf("os.Unsetenv() error = %v", err)
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(IdentityDirEnvVar, prev)
			}
		})

		if got := identityDir(); got != defaultIdentityDir {
			t.Fatalf("identityDir() = %q, want %q", got, defaultIdentityDir)
		}
	})

	t.Run("overridden", func(t *testing.T) {
		t.Setenv(IdentityDirEnvVar, "/custom/identity/dir")
		if got := identityDir(); got != "/custom/identity/dir" {
			t.Fatalf("identityDir() = %q, want %q", got, "/custom/identity/dir")
		}
	})
}
