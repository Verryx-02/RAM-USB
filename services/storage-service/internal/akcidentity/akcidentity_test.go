package akcidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Requirement: ST-F-11
func TestEncodeCertificateChain(t *testing.T) {
	tests := []struct {
		name  string
		chain [][]byte
		want  int // expected number of PEM CERTIFICATE blocks
	}{
		{name: "empty chain", chain: nil, want: 0},
		{name: "single leaf", chain: [][]byte{{0x01, 0x02, 0x03}}, want: 1},
		{name: "leaf plus intermediate", chain: [][]byte{{0x01}, {0x02}}, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := EncodeCertificateChain(tt.chain)

			rest := out
			got := 0
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					t.Fatalf("EncodeCertificateChain() produced block of type %q, want CERTIFICATE", block.Type)
				}
				got++
			}
			if got != tt.want {
				t.Fatalf("EncodeCertificateChain() produced %d CERTIFICATE blocks, want %d", got, tt.want)
			}
		})
	}
}

// Requirement: ST-F-11
func TestEncodePrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v, want nil", err)
	}

	pemBytes, err := EncodePrivateKey(key)
	if err != nil {
		t.Fatalf("EncodePrivateKey() error = %v, want nil", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("EncodePrivateKey() did not produce a decodable PRIVATE KEY PEM block: %q", pemBytes)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS8PrivateKey() error = %v, want nil", err)
	}
	parsedKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("x509.ParsePKCS8PrivateKey() = %T, want *ecdsa.PrivateKey", parsed)
	}
	if !parsedKey.Equal(key) {
		t.Fatal("EncodePrivateKey() round trip produced a different key")
	}
}

// Requirement: ST-F-11
func TestEncodePrivateKey_UnsupportedType(t *testing.T) {
	_, err := EncodePrivateKey("not a key")
	if err == nil {
		t.Fatal("EncodePrivateKey() with an unsupported key type error = nil, want non-nil")
	}
}

// Requirement: ST-F-11
//
// Byte-for-byte compatibility with cmd/authorized-keys-command/main.go's
// own parseConfig is what actually matters here - this test parses
// RenderConfig's output the exact same way that function does (rather than
// asserting on the literal string), so it stays correct even if
// RenderConfig's own formatting (whitespace, key order) changes without
// breaking the real contract.
func TestRenderConfig(t *testing.T) {
	got := RenderConfig("https://database-vault:8446", "/etc/storage-service/akc-client.crt", "/etc/storage-service/akc-client.key", "/etc/storage-service/akc-ca.crt")

	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("RenderConfig() produced a line with no '=': %q", line)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	want := map[string]string{
		"database_vault_url": "https://database-vault:8446",
		"client_cert":        "/etc/storage-service/akc-client.crt",
		"client_key":         "/etc/storage-service/akc-client.key",
		"client_ca":          "/etc/storage-service/akc-ca.crt",
	}
	for key, wantValue := range want {
		if values[key] != wantValue {
			t.Errorf("RenderConfig() key %q = %q, want %q", key, values[key], wantValue)
		}
	}
	if len(values) != len(want) {
		t.Errorf("RenderConfig() produced %d keys, want %d (got %v)", len(values), len(want), values)
	}
}

// Requirement: ST-F-11
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")

	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() first write error = %v, want nil", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v, want nil", err)
	}
	if string(got) != "first" {
		t.Fatalf("content after first write = %q, want %q", got, "first")
	}

	// A second write must fully replace the first, never append or leave
	// stale bytes behind.
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() second write error = %v, want nil", err)
	}
	got, err = os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v, want nil", err)
	}
	if string(got) != "second" {
		t.Fatalf("content after second write = %q, want %q", got, "second")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v, want nil", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file permissions = %v, want %v", info.Mode().Perm(), os.FileMode(0o600))
	}

	// No temporary file left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v, want nil", err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory contains %d entries after WriteFileAtomic(), want 1 (leftover temp file?): %v", len(entries), entries)
	}
}

// Requirement: ST-F-11
func TestWriteFileAtomic_DirectoryDoesNotExist(t *testing.T) {
	err := WriteFileAtomic(filepath.Join(t.TempDir(), "missing-dir", "target.txt"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("WriteFileAtomic() into a non-existent directory error = nil, want non-nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WriteFileAtomic() error = %v, want it to wrap os.ErrNotExist", err)
	}
}
