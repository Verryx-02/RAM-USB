package sshkey

import (
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Requirement: CL-F-01
func TestGenerateKeyPair_ProducesValidOpenSSHFormat(t *testing.T) {
	authorizedKeysLine, privateKeyPEM, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() error = %v, want nil", err)
	}

	// The public half must round-trip through the exact parser
	// pkg/validation (and Entry-Hub's EH-F-04) uses to accept an SSH
	// public key, so a client-generated key is guaranteed to validate
	// both locally (CL-F-09) and server-side.
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeysLine)); err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey(%q) error = %v, want nil", authorizedKeysLine, err)
	}
	if !strings.HasPrefix(authorizedKeysLine, "ssh-ed25519 ") {
		t.Errorf("authorizedKeysLine = %q, want ssh-ed25519 prefix", authorizedKeysLine)
	}

	block, rest := pem.Decode(privateKeyPEM)
	if block == nil {
		t.Fatalf("pem.Decode(privateKeyPEM) returned nil block")
	}
	if len(rest) != 0 {
		t.Errorf("pem.Decode left %d trailing bytes, want 0", len(rest))
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		t.Errorf("block.Type = %q, want OPENSSH PRIVATE KEY", block.Type)
	}
}

// Requirement: CL-F-01
func TestGenerateKeyPair_NeverProducesIdenticalKeys(t *testing.T) {
	line1, _, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() error = %v, want nil", err)
	}
	line2, _, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() error = %v, want nil", err)
	}
	if line1 == line2 {
		t.Errorf("two independent calls produced the same public key: %q", line1)
	}
}

// Requirement: CL-F-01
func TestStore_WritesFilesWithExpectedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode assertions do not apply on windows")
	}

	dir := t.TempDir()
	authorizedKeysLine, privateKeyPEM, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair() error = %v, want nil", err)
	}

	kp, err := store(dir, authorizedKeysLine, privateKeyPEM)
	if err != nil {
		t.Fatalf("store() error = %v, want nil", err)
	}

	privInfo, err := os.Stat(kp.PrivateKeyPath)
	if err != nil {
		t.Fatalf("os.Stat(private key) error = %v", err)
	}
	if got := privInfo.Mode().Perm(); got != privateKeyFileMode {
		t.Errorf("private key mode = %o, want %o", got, privateKeyFileMode)
	}

	pubInfo, err := os.Stat(kp.PublicKeyPath)
	if err != nil {
		t.Fatalf("os.Stat(public key) error = %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != publicKeyFileMode {
		t.Errorf("public key mode = %o, want %o", got, publicKeyFileMode)
	}

	if kp.AuthorizedKeysLine != authorizedKeysLine {
		t.Errorf("kp.AuthorizedKeysLine = %q, want %q", kp.AuthorizedKeysLine, authorizedKeysLine)
	}
}

// Requirement: CL-F-01
func TestLoad_NoExistingFiles(t *testing.T) {
	dir := t.TempDir()

	_, ok, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if ok {
		t.Errorf("Load() ok = true, want false when no files exist")
	}
}

// Requirement: CL-F-01
func TestLoad_IncompletePair(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, publicKeyFileName), []byte("ssh-ed25519 AAAA\n"), publicKeyFileMode); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	_, _, err := Load(dir)
	if !errors.Is(err, ErrKeyPairIncomplete) {
		t.Errorf("Load() error = %v, want ErrKeyPairIncomplete", err)
	}
}

// Requirement: CL-F-01
func TestEnsureKeyPair_GeneratesOnceThenReuses(t *testing.T) {
	dir := t.TempDir()

	first, err := EnsureKeyPair(dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair() first call error = %v, want nil", err)
	}

	second, err := EnsureKeyPair(dir)
	if err != nil {
		t.Fatalf("EnsureKeyPair() second call error = %v, want nil", err)
	}

	if first.AuthorizedKeysLine != second.AuthorizedKeysLine {
		t.Errorf("EnsureKeyPair() regenerated a key on the second call: first = %q, second = %q", first.AuthorizedKeysLine, second.AuthorizedKeysLine)
	}
}

// Requirement: CL-F-01
func TestConfigDir_ReturnsRAMUSBSubdirectory(t *testing.T) {
	tmp := t.TempDir()
	// os.UserConfigDir() reads different env vars per OS (XDG_CONFIG_HOME
	// on Linux, HOME on Darwin) - set both so this test is portable
	// without depending on which OS it runs on.
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("HOME", tmp)

	dir, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir() error = %v, want nil", err)
	}

	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir() error = %v, want nil", err)
	}
	want := filepath.Join(base, configDirName)
	if dir != want {
		t.Errorf("ConfigDir() = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v, want nil (directory should be created)", dir, err)
	}
	if !info.IsDir() {
		t.Errorf("%q exists but is not a directory", dir)
	}
}
