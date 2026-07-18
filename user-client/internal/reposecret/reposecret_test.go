package reposecret

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Requirement: CL-F-06
func TestEnsure_GeneratesOnceThenReuses(t *testing.T) {
	dir := t.TempDir()

	first, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure() first call error = %v, want nil", err)
	}
	if first == "" {
		t.Fatalf("Ensure() returned an empty password")
	}

	second, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure() second call error = %v, want nil", err)
	}
	if first != second {
		t.Errorf("Ensure() regenerated the password on the second call: first = %q, second = %q", first, second)
	}
}

// Requirement: CL-F-06
func TestEnsure_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode assertions do not apply on windows")
	}

	dir := t.TempDir()
	if _, err := Ensure(dir); err != nil {
		t.Fatalf("Ensure() error = %v, want nil", err)
	}

	info, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil {
		t.Fatalf("os.Stat() error = %v, want nil", err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Errorf("file mode = %o, want %o", got, fileMode)
	}
}

// Requirement: CL-F-06
func TestEnsure_DifferentDirsGetDifferentPasswords(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	a, err := Ensure(dirA)
	if err != nil {
		t.Fatalf("Ensure(dirA) error = %v, want nil", err)
	}
	b, err := Ensure(dirB)
	if err != nil {
		t.Fatalf("Ensure(dirB) error = %v, want nil", err)
	}
	if a == b {
		t.Errorf("Ensure() produced the same password for two independent directories")
	}
}
