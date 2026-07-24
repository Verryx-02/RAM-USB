// Package akcidentity holds the pure, testable logic behind
// cmd/identity-provisioner: encoding a live mTLS identity (obtained from
// pkg/pki, held only in memory by that long-lived process) into the PEM
// files and configuration file
// cmd/authorized-keys-command/main.go's fixed configPath contract expects
// on disk (KI-01, ST-F-11).
//
// Why a separate provisioning process exists at all, not something
// authorized-keys-command does for itself: authorized-keys-command is
// invoked by sshd as a brand-new subprocess on every single SFTP
// connection attempt and exits immediately after - CA-F-04's bootstrap
// token is single-use, so it cannot perform its own bootstrap exchange on
// every invocation, and it has no persistent process lifetime across which
// pkg/pki's automatic certificate renewal could run. cmd/identity-provisioner
// is instead a normal long-lived, s6-overlay-supervised process (the same
// shape as cmd/storage-service itself): it bootstraps once via pkg/pki,
// lets the vendor SDK's own renewal keep that identity current for the
// life of the container, and periodically re-encodes the CURRENT
// certificate/key to disk via this package's WriteFileAtomic - so every
// authorized-keys-command invocation, which reads fresh from disk on every
// call, always sees an unexpired identity without ever touching the
// bootstrap token itself again.
package akcidentity

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// EncodeCertificateChain PEM-encodes chain - a certificate chain in
// crypto/tls.Certificate.Certificate's own DER-bytes-per-entry,
// leaf-then-intermediates order (exactly what
// github.com/smallstep/certificates@v0.30.2/ca's TLSRenewer.GetClientCertificate
// returns) - as one CERTIFICATE PEM block per entry, concatenated in the
// same order. tls.LoadX509KeyPair (authorized-keys-command's own reader,
// buildClient in cmd/authorized-keys-command/main.go) accepts exactly this
// concatenated-PEM-chain shape for its certFile argument.
func EncodeCertificateChain(chain [][]byte) []byte {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}
	return out
}

// EncodePrivateKey PEM-encodes key (as returned alongside the certificate
// chain by pkg/pki's bootstrapped identity - an ECDSA key, per
// github.com/smallstep/certificates@v0.30.2's own default key algorithm,
// but this function is not hardcoded to that: x509.MarshalPKCS8PrivateKey
// accepts any of the crypto.Signer implementations that package can
// return) into a PEM-encoded PKCS#8 block, the format
// tls.LoadX509KeyPair's keyFile argument (authorized-keys-command's own
// reader) accepts.
func EncodePrivateKey(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("akcidentity: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// RenderConfig renders the exact "key = value" text
// cmd/authorized-keys-command/main.go's parseConfig expects at its fixed
// configPath - the four keys that function requires (database_vault_url,
// client_cert, client_key, client_ca), one per line, nothing else. Must
// stay byte-for-byte compatible with that function's own parsing rules
// (see its own doc comment) if either side ever changes.
func RenderConfig(databaseVaultURL, certPath, keyPath, caPath string) string {
	return fmt.Sprintf(
		"database_vault_url = %s\nclient_cert = %s\nclient_key = %s\nclient_ca = %s\n",
		databaseVaultURL, certPath, keyPath, caPath,
	)
}

// WriteFileAtomic writes data to path with permissions perm, atomically
// (write to a temporary file in the same directory, then rename over the
// destination) rather than truncating path in place. This matters here
// specifically because authorized-keys-command reads these exact files
// fresh on every single SFTP connection attempt (its own doc comment,
// cmd/authorized-keys-command/main.go) - an in-place truncate-then-write
// would leave a window where a concurrent read sees a partially-written or
// empty file, an avoidable failure this function's atomicity closes off
// (a failure that would fail closed either way, per RD-04, but there is no
// reason to accept it when the fix is this cheap).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".akcidentity-*")
	if err != nil {
		return fmt.Errorf("akcidentity: create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	// A failure between here and the final rename must not leave the
	// temporary file behind - os.Remove on an already-renamed-away path
	// harmlessly no-ops (ErrNotExist), so this defer is unconditional
	// rather than gated on an error flag.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("akcidentity: write temp file %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("akcidentity: chmod temp file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("akcidentity: close temp file %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("akcidentity: rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}
