package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// Requirement: CA-F-04
//
// A malformed token is rejected by local JWT parsing alone, before any
// network call - same reasoning as TestNewClient_MalformedToken/
// TestNewServer_MalformedToken in pki_test.go.
func TestRootCA_MalformedToken(t *testing.T) {
	_, err := RootCA(context.Background(), "not-a-real-token")
	if err == nil {
		t.Fatal("RootCA() with a malformed token error = nil, want non-nil")
	}
}

// Requirement: ST-F-11
//
// End-to-end against the real Certificate-Authority: RootCA returns a
// PEM-encoded certificate matching this dev deployment's own CA name, and -
// the property that actually matters for this function's whole reason to
// exist - calling it does NOT consume token's single use: a subsequent
// NewClient call with the exact same token still succeeds.
func TestRootCA_RealCA(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)
	token := generateTestToken(t, caURL, container, "pki-test-rootca")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rootPEM, err := RootCA(ctx, token)
	if err != nil {
		t.Fatalf("RootCA() error = %v, want nil", err)
	}

	block, _ := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("RootCA() did not return a decodable CERTIFICATE PEM block: %q", rootPEM)
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(RootCA() output) error = %v, want nil", err)
	}

	found := false
	for _, org := range root.Subject.Organization {
		if org == caName {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("root certificate's subject organization = %v, want to contain %q", root.Subject.Organization, caName)
	}

	// The single-use bootstrap token must still be usable after RootCA -
	// proof that RootCA never touched the CA's Sign endpoint.
	if _, err := NewClient(ctx, token); err != nil {
		t.Fatalf("NewClient() with the same token AFTER RootCA() error = %v, want nil (RootCA must not consume the token's single use)", err)
	}
}
