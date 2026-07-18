// Package reposecret sources restic's own repository-encryption password
// (distinct from the user's RAM-USB login password - restic requires one
// to create or open any repository at all, and refuses to run without
// it).
//
// DESIGN DECISION FLAGGED FOR REVIEW: the SRS does not specify where this
// password comes from or how it is stored - CL-F-06/CL-F-07 only say
// "invoke restic backup/restore ... authenticating with the SSH private
// key generated in CL-F-01", which covers restic's *transport*
// authentication (SFTP), not restic's own separate repository-encryption
// secret. This package's chosen approach: generate a random 32-byte value
// once, on first use, and persist it at os.UserConfigDir()/ram-usb/
// restic-password with the same 0600 permissions as CL-F-01's private key
// - reusing it on every later invocation, exactly like sshkey.
// EnsureKeyPair's own reuse-if-present logic, because restic cannot
// decrypt a repository's existing snapshots with a different password
// than the one used to create it. This file never leaves the local
// machine and is never transmitted to any system component, consistent
// with RNF-SEC-01/RD-01's "plaintext sensitive data stays confined to the
// client" - but the storage location and format are this session's
// judgment call, not a value fixed by the SRS.
package reposecret

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// fileName is the fixed file name this package stores the repository
// password under, inside the directory a caller supplies (in practice,
// sshkey.ConfigDir()'s own ram-usb directory - the same local, per-user
// config directory, not a separate one).
const fileName = "restic-password"

// fileMode restricts the password file to owner read/write only, matching
// CL-F-01's private key file's own permissions.
const fileMode = 0o600

// passwordBytes is the amount of random data generated for a new
// repository password before base64 encoding - 32 bytes (256 bits) is
// generously more entropy than restic's own repository encryption
// (AES-256) can use, not a value the SRS specifies.
const passwordBytes = 32

// Ensure returns the repository password stored under dir, generating and
// storing a new random one on first use if none exists yet.
func Ensure(dir string) (string, error) {
	path := filepath.Join(dir, fileName)

	existing, err := os.ReadFile(path) //nolint:gosec // G304: path is dir (the caller's own ram-usb config directory) joined with this package's own fixed fileName constant, never externally-supplied input.
	if err == nil {
		return string(existing), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("reposecret: read existing password: %w", err)
	}

	raw := make([]byte, passwordBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("reposecret: generate password: %w", err)
	}
	password := base64.StdEncoding.EncodeToString(raw)

	if err := os.WriteFile(path, []byte(password), fileMode); err != nil {
		return "", fmt.Errorf("reposecret: write password: %w", err)
	}
	return password, nil
}
