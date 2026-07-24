package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// Requirement: PKI-F-01
func TestTrustPool(t *testing.T) {
	ca, err := NewTestCA()
	if err != nil {
		t.Fatalf("NewTestCA() error = %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	tests := []struct {
		name    string
		write   func(t *testing.T, dir string) string // returns the path to pass to TrustPool
		wantErr bool
	}{
		{
			name: "valid PEM certificate",
			write: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "ca.pem")
				if err := os.WriteFile(path, caPEM, 0o600); err != nil {
					t.Fatalf("os.WriteFile() error = %v", err)
				}
				return path
			},
			wantErr: false,
		},
		{
			name: "file does not exist",
			write: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "does-not-exist.pem")
			},
			wantErr: true,
		},
		{
			name: "empty file parses to zero certificates",
			write: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "empty.pem")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatalf("os.WriteFile() error = %v", err)
				}
				return path
			},
			wantErr: true,
		},
		{
			name: "malformed PEM parses to zero certificates",
			write: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "malformed.pem")
				if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
					t.Fatalf("os.WriteFile() error = %v", err)
				}
				return path
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.write(t, dir)

			pool, err := TrustPool(path)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("TrustPool(%q) error = nil, want error", path)
				}
				if pool != nil {
					t.Fatalf("TrustPool(%q) pool = %v, want nil on error", path, pool)
				}
				return
			}

			if err != nil {
				t.Fatalf("TrustPool(%q) error = %v, want nil", path, err)
			}
			if pool == nil {
				t.Fatalf("TrustPool(%q) pool = nil, want non-nil", path)
			}

			// The returned pool must actually trust the certificate it was
			// built from - verifying a leaf issued by ca against it must
			// succeed.
			leaf, err := ca.IssueLeaf("TestOrg", "trust-pool-test")
			if err != nil {
				t.Fatalf("IssueLeaf() error = %v", err)
			}
			leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
			if err != nil {
				t.Fatalf("x509.ParseCertificate() error = %v", err)
			}
			if _, err := leafCert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
				t.Fatalf("leafCert.Verify() error = %v, want nil (pool should trust ca)", err)
			}
		})
	}
}
