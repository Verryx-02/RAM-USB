package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mtls"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/akcidentity"
)

// Requirement: ST-F-11
func TestResolve(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		handler    http.HandlerFunc
		wantLine   string
		wantOK     bool
		ctxTimeout time.Duration
	}{
		{
			name: "valid username, successful lookup",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ssh_public_key": "ssh-ed25519 AAAAC3 comment"}`))
			},
			wantLine: "ssh-ed25519 AAAAC3 comment",
			wantOK:   true,
		},
		{
			name: "database-vault reports not found",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantOK: false,
		},
		{
			name: "database-vault lookup fails (unexpected status)",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantOK: false,
		},
		{
			name: "database-vault lookup fails (malformed body)",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`not json`))
			},
			wantOK: false,
		},
		{
			name: "context deadline exceeded",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(200 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			},
			wantOK:     false,
			ctxTimeout: 10 * time.Millisecond,
		},
		{
			name: "malformed username, server never contacted",
			arg:  "not-a-valid-username",
			handler: func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatal("server should never be contacted for a malformed username")
			},
			wantOK: false,
		},
		{
			name: "empty username, server never contacted",
			arg:  "",
			handler: func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatal("server should never be contacted for an empty username")
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}

			line, ok := Resolve(ctx, server.Client(), server.URL, tt.arg)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && line != tt.wantLine {
				t.Fatalf("line = %q, want %q", line, tt.wantLine)
			}
			if !ok && line != "" {
				t.Fatalf("expected empty line on failure, got %q", line)
			}
		})
	}
}

// Requirement: ST-F-11
func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    config
		wantErr bool
	}{
		{
			name: "well-formed config",
			input: strings.Join([]string{
				"# comment line, ignored",
				"database_vault_url = https://database-vault.internal:8444",
				"client_cert = /etc/storage-service/authorized-keys-command.crt",
				"client_key = /etc/storage-service/authorized-keys-command.key",
				"client_ca = /etc/storage-service/ca.crt",
				"",
			}, "\n"),
			want: config{
				databaseVaultURL: "https://database-vault.internal:8444",
				clientCertPath:   "/etc/storage-service/authorized-keys-command.crt",
				clientKeyPath:    "/etc/storage-service/authorized-keys-command.key",
				clientCAPath:     "/etc/storage-service/ca.crt",
			},
		},
		{
			name:    "missing required key",
			input:   "database_vault_url = https://database-vault.internal:8444\n",
			wantErr: true,
		},
		{
			name:    "empty file",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed line, no equals sign",
			input:   "database_vault_url https://database-vault.internal:8444\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConfig(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (config: %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Requirement: ST-F-11
//
// Reproduces a real bug found live this session (a real deployment against
// the real Certificate-Authority): every certificate this project's CA
// issues carries the organization string as its SAN, never the dialed
// network hostname (third-party/certificate-authority/config/
// organization.x509.tpl) - so a client that leaves ServerName at its
// zero value (defaulting to the dialed address, "database-vault") fails
// crypto/tls's own independent hostname check with "certificate is valid
// for DatabaseVault, not database-vault" before PKI-F-02's
// mtls.ClientConfig organization check ever runs. This test's server
// certificate deliberately mirrors that real shape (organization
// "DatabaseVault", SAN ["DatabaseVault"], dialed as "localhost") -
// mtls.TestCA.IssueLeaf's own doc comment documents this exact pattern for
// exactly this kind of test.
func TestBuildClient_ForcesServerNameToOrganization(t *testing.T) {
	ca, err := mtls.NewTestCA()
	if err != nil {
		t.Fatalf("mtls.NewTestCA() error = %v, want nil", err)
	}

	serverLeaf, err := ca.IssueLeaf(organizationDatabaseVault, "database-vault-server", organizationDatabaseVault)
	if err != nil {
		t.Fatalf("IssueLeaf(server) error = %v, want nil", err)
	}
	clientLeaf, err := ca.IssueLeaf("StorageService", "authorized-keys-command-client")
	if err != nil {
		t.Fatalf("IssueLeaf(client) error = %v, want nil", err)
	}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewUnstartedServer(next)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()
	baseURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.crt")

	if err := akcidentity.WriteFileAtomic(certPath, akcidentity.EncodeCertificateChain(clientLeaf.Certificate), 0o600); err != nil {
		t.Fatalf("write client cert: %v", err)
	}
	keyPEM, err := akcidentity.EncodePrivateKey(clientLeaf.PrivateKey)
	if err != nil {
		t.Fatalf("encode client key: %v", err)
	}
	if err := akcidentity.WriteFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	if err := akcidentity.WriteFileAtomic(caPath, ca.CertPEM(), 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}

	cfg := config{
		databaseVaultURL: baseURL,
		clientCertPath:   certPath,
		clientKeyPath:    keyPath,
		clientCAPath:     caPath,
	}

	client, err := buildClient(cfg)
	if err != nil {
		t.Fatalf("buildClient() error = %v, want nil", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v, want nil", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v, want nil - buildClient's TLSClientConfig.ServerName must be forced to the organization, or this real certificate's SAN mismatch fails hostname verification before PKI-F-02's organization check ever runs", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !called {
		t.Fatal("server handler was never called")
	}
}
