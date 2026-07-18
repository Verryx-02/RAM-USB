package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
			handler: func(w http.ResponseWriter, r *http.Request) {
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
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantOK: false,
		},
		{
			name: "database-vault lookup fails (unexpected status)",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantOK: false,
		},
		{
			name: "database-vault lookup fails (malformed body)",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`not json`))
			},
			wantOK: false,
		},
		{
			name: "context deadline exceeded",
			arg:  "user7k2m9x",
			handler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(200 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			},
			wantOK:     false,
			ctxTimeout: 10 * time.Millisecond,
		},
		{
			name: "malformed username, server never contacted",
			arg:  "not-a-valid-username",
			handler: func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("server should never be contacted for a malformed username")
			},
			wantOK: false,
		},
		{
			name: "empty username, server never contacted",
			arg:  "",
			handler: func(w http.ResponseWriter, r *http.Request) {
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
