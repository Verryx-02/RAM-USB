package restic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Requirement: CL-F-11
func TestWriteKnownHosts_Success(t *testing.T) {
	dir := t.TempDir()
	hostPublicKeyLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleTestHostKeyOnly root@storage-service"

	path, err := WriteKnownHosts(dir, "storage-service.mesh.ts.net", hostPublicKeyLine)
	if err != nil {
		t.Fatalf("WriteKnownHosts() error = %v, want nil", err)
	}
	if path != filepath.Join(dir, "known_hosts") {
		t.Errorf("path = %q, want %q", path, filepath.Join(dir, "known_hosts"))
	}

	got, err := os.ReadFile(path) //nolint:gosec // G304: path is exactly what WriteKnownHosts (this test's own subject) just returned, under t.TempDir() - not externally-supplied input.
	if err != nil {
		t.Fatalf("read written known_hosts: %v", err)
	}
	want := "[storage-service.mesh.ts.net]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleTestHostKeyOnly\n"
	if string(got) != want {
		t.Errorf("known_hosts content = %q, want %q", got, want)
	}
}

// Requirement: CL-F-11
func TestWriteKnownHosts_RejectsMalformedKey(t *testing.T) {
	dir := t.TempDir()

	if _, err := WriteKnownHosts(dir, "storage-service.mesh.ts.net", "not-a-valid-key-line"); err == nil {
		t.Error("WriteKnownHosts() error = nil, want non-nil for a key line with no base64 field")
	}
}

// Requirement: CL-F-11
//
// This test proves the bracketed "[host]:port" entry WriteKnownHosts
// produces is not merely plausible-looking, but actually recognized by a
// real OpenSSH toolchain for a non-default port - "ssh-keygen -F" performs
// the exact same known_hosts lookup ssh itself does when connecting. It
// is skipped if ssh-keygen is not on PATH (e.g. some minimal CI images).
func TestWriteKnownHosts_RealSSHKeygenRecognizesBracketedEntry(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}

	dir := t.TempDir()
	hostPublicKeyLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleTestHostKeyOnly root@storage-service"
	path, err := WriteKnownHosts(dir, "storage-service.mesh.ts.net", hostPublicKeyLine)
	if err != nil {
		t.Fatalf("WriteKnownHosts() error = %v, want nil", err)
	}

	// A lookup by the bracketed "[host]:port" form - what ssh itself
	// queries when connecting to a non-default port - must find the entry.
	ctx := context.Background()
	//nolint:gosec // G204: fixed argv, "path" is exactly what WriteKnownHosts (this test's own subject) just returned, under t.TempDir() - not externally-supplied input.
	if err := exec.CommandContext(ctx, "ssh-keygen", "-F", "[storage-service.mesh.ts.net]:2222", "-f", path).Run(); err != nil {
		t.Errorf("ssh-keygen -F did not find the bracketed entry: %v", err)
	}

	// A lookup by the bare hostname (i.e. what a default-port-22 entry
	// would have matched) must NOT find it - proving the port is actually
	// encoded in the entry, not just cosmetically present.
	//nolint:gosec // G204: fixed argv, "path" is exactly what WriteKnownHosts (this test's own subject) just returned, under t.TempDir() - not externally-supplied input.
	if err := exec.CommandContext(ctx, "ssh-keygen", "-F", "storage-service.mesh.ts.net", "-f", path).Run(); err == nil {
		t.Error("ssh-keygen -F matched the bare hostname, want it to require the bracketed [host]:port form")
	}
}
