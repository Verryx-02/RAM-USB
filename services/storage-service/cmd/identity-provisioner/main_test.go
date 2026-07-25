package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeLeaf generates a throwaway self-signed ECDSA certificate/key pair,
// standing in for pkg/pki's own real CA-issued identity - this test only
// needs SOMETHING refreshCertificate can encode and write to disk, not a
// real chain of trust.
func fakeLeaf(t *testing.T) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v, want nil", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"StorageService"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v, want nil", err)
	}

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Requirement: ST-F-11
func TestRefreshCertificate(t *testing.T) {
	dir := t.TempDir()
	certFilePath := filepath.Join(dir, "akc-client.crt")
	keyFilePath := filepath.Join(dir, "akc-client.key")

	leaf := fakeLeaf(t)
	getClientCertificate := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return leaf, nil
	}

	if err := refreshCertificate(getClientCertificate, certFilePath, keyFilePath); err != nil {
		t.Fatalf("refreshCertificate() error = %v, want nil", err)
	}

	certPEM, err := os.ReadFile(certFilePath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile(cert) error = %v, want nil", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate file did not decode as a CERTIFICATE PEM block: %q", certPEM)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v, want nil", err)
	}

	keyPEM, err := os.ReadFile(keyFilePath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("os.ReadFile(key) error = %v, want nil", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("key file did not decode as a PRIVATE KEY PEM block: %q", keyPEM)
	}

	info, err := os.Stat(keyFilePath)
	if err != nil {
		t.Fatalf("os.Stat(key) error = %v, want nil", err)
	}
	if info.Mode().Perm() != keyFilePerm {
		t.Fatalf("key file permissions = %v, want %v", info.Mode().Perm(), keyFilePerm)
	}
}

// Requirement: ST-F-11
//
// A getClientCertificate failure (e.g. pkg/pki's renewal not having
// completed yet) must fail closed (RD-04) - no partial cert/key pair left
// on disk from an incomplete refresh.
func TestRefreshCertificate_GetClientCertificateError(t *testing.T) {
	dir := t.TempDir()
	certFilePath := filepath.Join(dir, "akc-client.crt")
	keyFilePath := filepath.Join(dir, "akc-client.key")

	errFake := errors.New("fake: certificate not ready")
	getClientCertificate := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, errFake
	}

	err := refreshCertificate(getClientCertificate, certFilePath, keyFilePath)
	if !errors.Is(err, errFake) {
		t.Fatalf("refreshCertificate() error = %v, want it to wrap %v", err, errFake)
	}

	if _, statErr := os.Stat(certFilePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("certificate file exists after a failed refresh, want none")
	}
	if _, statErr := os.Stat(keyFilePath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("key file exists after a failed refresh, want none")
	}
}
