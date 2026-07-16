package pki

import (
	"context"
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
