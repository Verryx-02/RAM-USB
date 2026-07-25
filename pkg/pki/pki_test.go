package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

// Requirement: CA-F-04
func TestLoadBootstrapToken(t *testing.T) {
	tests := []struct {
		name      string
		setEnv    bool
		envValue  string
		wantToken string
		wantErr   error
	}{
		{
			name:      "present and non-empty",
			setEnv:    true,
			envValue:  "a-real-bootstrap-token",
			wantToken: "a-real-bootstrap-token",
			wantErr:   nil,
		},
		{
			name:     "set to empty string",
			setEnv:   true,
			envValue: "",
			wantErr:  ErrBootstrapTokenMissing,
		},
		{
			name:    "unset",
			setEnv:  false,
			wantErr: ErrBootstrapTokenMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv cannot unset a variable (it always calls
			// os.Setenv under the hood), so the "unset" case is handled
			// with a manual os.Unsetenv + restore instead — same gotcha
			// already documented for encryption.LoadMasterKey's tests.
			if tt.setEnv {
				t.Setenv(BootstrapTokenEnvVar, tt.envValue)
			} else {
				prevValue, hadValue := os.LookupEnv(BootstrapTokenEnvVar)
				if err := os.Unsetenv(BootstrapTokenEnvVar); err != nil {
					t.Fatalf("os.Unsetenv: %v", err)
				}
				t.Cleanup(func() {
					if hadValue {
						_ = os.Setenv(BootstrapTokenEnvVar, prevValue)
					}
				})
			}

			token, err := LoadBootstrapToken()

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("LoadBootstrapToken() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadBootstrapToken() unexpected error = %v", err)
			}
			if token != tt.wantToken {
				t.Fatalf("LoadBootstrapToken() = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

// Requirement: CA-F-04
//
// NewServer/NewClient's error path for a malformed token is genuinely
// pure logic reachable with no real Certificate-Authority: the vendor
// SDK (ca.Bootstrap, called internally by both) parses and validates the
// token's JWT claims locally, and rejects a malformed one before any
// network call is made (confirmed by reading
// github.com/smallstep/certificates/ca's bootstrap.go — Bootstrap parses
// the token with jose.ParseSigned and checks the "sha"/"aud" claims
// before ever constructing an HTTP request).
func TestNewServer_MalformedToken(t *testing.T) {
	_, err := NewServer(context.Background(), "not-a-real-token", &http.Server{ReadHeaderTimeout: 5 * time.Second})
	if err == nil {
		t.Fatal("NewServer() with a malformed token error = nil, want non-nil")
	}
}

// Requirement: CA-F-04
func TestNewClient_MalformedToken(t *testing.T) {
	_, err := NewClient(context.Background(), "not-a-real-token")
	if err == nil {
		t.Fatal("NewClient() with a malformed token error = nil, want non-nil")
	}
}

// Requirement: NET-F-02
//
// NewServer's *tls.Config must enforce TLS 1.3, unconditionally
// (forceTLS13 in pki.go) — the vendored SDK's own default (ca/tls.go's
// getDefaultTLSConfig) falls back to TLS 1.2 whenever the CA's own
// TLSOptions don't set MinVersion, which RAM-USB's Certificate-Authority
// config does not.
func TestNewServer_RealCA_EnforcesTLS13(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)
	token := generateTestToken(t, caURL, container, "pki-test-server-tls13")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := NewServer(ctx, token, &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewServer() error = %v, want nil", err)
	}
	if server.TLSConfig == nil {
		t.Fatal("NewServer() TLSConfig = nil, want non-nil")
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("NewServer() TLSConfig.MinVersion = %#x, want %#x (tls.VersionTLS13)", server.TLSConfig.MinVersion, tls.VersionTLS13)
	}
}

// Requirement: NET-F-02
//
// Same guarantee as TestNewServer_RealCA_EnforcesTLS13, for the outbound
// client side (NewClient/NewClientWithDialer's shared bootstrap path).
func TestNewClient_RealCA_EnforcesTLS13(t *testing.T) {
	caURL, container := skipUnlessCAConfigured(t)
	token := generateTestToken(t, caURL, container, "pki-test-client-tls13")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client, err := NewClient(ctx, token)
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("client.Transport.TLSClientConfig = nil, want non-nil")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client.Transport.TLSClientConfig.MinVersion = %#x, want %#x (tls.VersionTLS13)", transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
}
