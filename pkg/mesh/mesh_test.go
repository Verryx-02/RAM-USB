package mesh

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
)

// Requirement: SS-F-01, DV-F-01
//
// Up fails closed (RD-04) on any missing config field, before ever
// attempting a real network join - each row leaves exactly one required
// field empty.
func TestUp_RejectsIncompleteConfig(t *testing.T) {
	valid := Config{
		Dir:        t.TempDir(),
		Hostname:   "test-node",
		ControlURL: "https://headscale:8080",
		AuthKey:    "test-auth-key",
	}

	tests := []struct {
		name    string
		mutate  func(c Config) Config
		wantErr string
	}{
		{
			name:    "empty Dir",
			mutate:  func(c Config) Config { c.Dir = ""; return c },
			wantErr: "Dir must not be empty",
		},
		{
			name:    "empty Hostname",
			mutate:  func(c Config) Config { c.Hostname = ""; return c },
			wantErr: "Hostname must not be empty",
		},
		{
			name:    "empty ControlURL",
			mutate:  func(c Config) Config { c.ControlURL = ""; return c },
			wantErr: "ControlURL must not be empty",
		},
		{
			name:    "empty AuthKey",
			mutate:  func(c Config) Config { c.AuthKey = ""; return c },
			wantErr: "AuthKey must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.mutate(valid)

			_, err := Up(context.Background(), cfg)
			if err == nil {
				t.Fatal("Up() error = nil, want a validation error")
			}
			if got := err.Error(); !strings.Contains(got, tt.wantErr) {
				t.Fatalf("Up() error = %q, want it to contain %q", got, tt.wantErr)
			}
		})
	}
}

// Requirement: SS-F-01, DV-F-01, RD-04
//
// trustControlCA fails closed on an unreadable or malformed
// Config.ControlCAFile, before ever mutating process state - see the
// package doc comment, "Control-plane certificate trust in a distroless
// container".
func TestTrustControlCA_FailsClosedOnInvalidFile(t *testing.T) {
	tests := []struct {
		name      string
		writeFile func(t *testing.T) string
		wantErr   string
	}{
		{
			name: "missing file",
			writeFile: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "does-not-exist.pem")
			},
			wantErr: "read ControlCAFile",
		},
		{
			name: "malformed PEM",
			writeFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "bad.pem")
				if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
					t.Fatalf("write test file: %v", err)
				}
				return path
			},
			wantErr: "contains no valid PEM certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.writeFile(t)

			err := trustControlCA(path)
			if err == nil {
				t.Fatal("trustControlCA() error = nil, want an error")
			}
			if got := err.Error(); !strings.Contains(got, tt.wantErr) {
				t.Fatalf("trustControlCA() error = %q, want it to contain %q", got, tt.wantErr)
			}
		})
	}
}

// Requirement: SS-F-01, DV-F-01
//
// trustControlCA accepts a well-formed PEM certificate and points
// SSL_CERT_FILE at it - the exact mechanism crypto/x509.SystemCertPool
// documents for Linux (see the package doc comment), which is what lets
// tsnet's control-plane dial trust a dev-only self-signed Headscale
// certificate with no OS-level trust store to write into.
func TestTrustControlCA_ValidFile_SetsSSLCertFile(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")

	path := writeTestLeafPEM(t)

	if err := trustControlCA(path); err != nil {
		t.Fatalf("trustControlCA() error = %v, want nil", err)
	}
	if got := os.Getenv("SSL_CERT_FILE"); got != path {
		t.Fatalf("SSL_CERT_FILE = %q, want %q", got, path)
	}
}

// writeTestLeafPEM writes a freshly issued, well-formed leaf certificate
// (PEM-encoded) to a temp file and returns its path - a stand-in for the
// dev-only self-signed Headscale certificate this package's
// Config.ControlCAFile mechanism exists for.
func writeTestLeafPEM(t *testing.T) string {
	t.Helper()

	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("mtls.NewTestCA() error = %v", err)
	}
	leaf, err := ca.IssueLeaf("headscale", "test-leaf")
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}

	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})

	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write leaf PEM: %v", err)
	}
	return path
}
