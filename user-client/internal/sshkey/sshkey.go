// Package sshkey implements CL-F-01: autonomous generation and local
// storage of the ed25519 SSH key pair the Client uses for every later
// Storage-Service SFTP connection (CL-F-06/CL-F-07). The private key is
// never returned in a form meant for transmission - callers that need to
// send the client's identity to Entry-Hub use only the AuthorizedKeysLine
// field (CL-F-02), never PrivateKeyPath's contents.
//
// Key material is generated with crypto/ed25519 (the only algorithm this
// package supports - the SRS does not call for algorithm choice, ed25519
// is a reasonable modern default with no key-size parameter to get wrong)
// and converted to the exact OpenSSH wire formats
// (golang.org/x/crypto/ssh.MarshalAuthorizedKey for the public key,
// ssh.MarshalPrivateKey for the private key) so the generated public key
// round-trips through pkg/validation's ssh.ParseAuthorizedKey call
// (CL-F-09, EH-F-04) exactly like any other well-formed authorized_keys
// line.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// configDirName is the RAM-USB-specific subdirectory created under
// os.UserConfigDir() (~/.config/ram-usb on Linux, ~/Library/Application
// Support/ram-usb on macOS) - this exact location was agreed with the
// user directly, not derived from the SRS, which does not specify a
// storage path.
const configDirName = "ram-usb"

// privateKeyFileName and publicKeyFileName are the fixed file names this
// package stores the generated key pair under, inside the directory
// ConfigDir returns.
const (
	privateKeyFileName = "id_ed25519"
	publicKeyFileName  = "id_ed25519.pub"
)

// privateKeyFileMode restricts the private key file to owner
// read/write only, matching OpenSSH's own convention that a private key
// file be inaccessible to any other local user.
const privateKeyFileMode = 0o600

// publicKeyFileMode is a conventional world-readable mode for a public
// key file - it carries no secret material.
const publicKeyFileMode = 0o644

// ErrKeyPairIncomplete is returned by Load when exactly one of the two
// expected files exists on disk (e.g. the private key was deleted but the
// public key was not, or vice versa) - a state EnsureKeyPair refuses to
// silently repair by regenerating, since that would either overwrite a
// still-valid private key or silently discard one, per fail-secure
// (RD-04).
var ErrKeyPairIncomplete = errors.New("sshkey: only one of the private/public key files exists")

// KeyPair holds the paths and public material of a generated or loaded
// key pair. PrivateKeyPath is never read to construct any outbound
// request - only CL-F-06/CL-F-07's restic invocation and this package's
// own store use it.
type KeyPair struct {
	// PrivateKeyPath is the absolute path to the OpenSSH-format PEM
	// private key file.
	PrivateKeyPath string

	// PublicKeyPath is the absolute path to the authorized_keys-format
	// public key file.
	PublicKeyPath string

	// AuthorizedKeysLine is the exact "ssh-ed25519 AAAA...\n" line
	// (CL-F-02's payload, and pkg/validation's expected input shape).
	AuthorizedKeysLine string
}

// ConfigDir returns the RAM-USB configuration directory
// (os.UserConfigDir()/ram-usb), creating it (and any missing parent) if it
// does not already exist.
func ConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("sshkey: resolve user config directory: %w", err)
	}
	dir := filepath.Join(base, configDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("sshkey: create config directory: %w", err)
	}
	return dir, nil
}

// generateKeyPair creates a new ed25519 key pair and returns it encoded in
// OpenSSH wire format: an authorized_keys line for the public half, and a
// PEM-encoded OPENSSH PRIVATE KEY block for the private half. It performs
// no filesystem I/O - store is the caller that writes these bytes to
// disk, keeping the pure key-generation logic independently testable.
func generateKeyPair() (authorizedKeysLine string, privateKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("sshkey: generate ed25519 key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("sshkey: convert public key: %w", err)
	}
	authorizedKeysLine = string(ssh.MarshalAuthorizedKey(sshPub))

	block, err := ssh.MarshalPrivateKey(priv, "ram-usb")
	if err != nil {
		return "", nil, fmt.Errorf("sshkey: marshal private key: %w", err)
	}
	privateKeyPEM = pem.EncodeToMemory(block)

	return authorizedKeysLine, privateKeyPEM, nil
}

// store writes authorizedKeysLine and privateKeyPEM to dir under this
// package's fixed file names, with the private key file restricted to
// owner-only access (CL-F-01: "never transmitting the private key" is
// reinforced locally too - no other local account can read it).
func store(dir, authorizedKeysLine string, privateKeyPEM []byte) (KeyPair, error) {
	privPath := filepath.Join(dir, privateKeyFileName)
	pubPath := filepath.Join(dir, publicKeyFileName)

	if err := os.WriteFile(privPath, privateKeyPEM, privateKeyFileMode); err != nil {
		return KeyPair{}, fmt.Errorf("sshkey: write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(authorizedKeysLine), publicKeyFileMode); err != nil {
		return KeyPair{}, fmt.Errorf("sshkey: write public key: %w", err)
	}

	return KeyPair{
		PrivateKeyPath:     privPath,
		PublicKeyPath:      pubPath,
		AuthorizedKeysLine: authorizedKeysLine,
	}, nil
}

// Load reads an existing key pair back from dir, without generating
// anything. It reports (KeyPair{}, false, nil) if neither file exists yet,
// and ErrKeyPairIncomplete if exactly one of the two exists.
func Load(dir string) (KeyPair, bool, error) {
	privPath := filepath.Join(dir, privateKeyFileName)
	pubPath := filepath.Join(dir, publicKeyFileName)

	_, privErr := os.Stat(privPath)
	_, pubErr := os.Stat(pubPath)
	privExists := privErr == nil
	pubExists := pubErr == nil

	switch {
	case !privExists && !pubExists:
		return KeyPair{}, false, nil
	case privExists != pubExists:
		return KeyPair{}, false, ErrKeyPairIncomplete
	}

	pubBytes, err := os.ReadFile(pubPath) //nolint:gosec // G304: pubPath is dir (the caller's own ram-usb config directory, from ConfigDir) joined with this package's own fixed publicKeyFileName constant, never externally-supplied input.
	if err != nil {
		return KeyPair{}, false, fmt.Errorf("sshkey: read public key: %w", err)
	}

	return KeyPair{
		PrivateKeyPath:     privPath,
		PublicKeyPath:      pubPath,
		AuthorizedKeysLine: string(pubBytes),
	}, true, nil
}

// EnsureKeyPair implements CL-F-01 end to end: reuse an existing key pair
// under dir if one is already fully present (so repeated invocations -
// e.g. a later login or backup command - do not silently invalidate a key
// already registered with Entry-Hub), or generate and store a new one
// otherwise.
func EnsureKeyPair(dir string) (KeyPair, error) {
	existing, ok, err := Load(dir)
	if err != nil {
		return KeyPair{}, err
	}
	if ok {
		return existing, nil
	}

	authorizedKeysLine, privateKeyPEM, err := generateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}

	return store(dir, authorizedKeysLine, privateKeyPEM)
}
