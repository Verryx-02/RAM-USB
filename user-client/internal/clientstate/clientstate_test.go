package clientstate

import "testing"

// Requirement: CL-F-06 (POSIX username persistence is what lets a later,
// separate backup/restore invocation address the right Storage-Service
// chroot without the user re-supplying it)
func TestSaveAndLoadPosixUsername(t *testing.T) {
	dir := t.TempDir()

	if err := SavePosixUsername(dir, "user000042"); err != nil {
		t.Fatalf("SavePosixUsername() error = %v, want nil", err)
	}

	got, ok, err := LoadPosixUsername(dir)
	if err != nil {
		t.Fatalf("LoadPosixUsername() error = %v, want nil", err)
	}
	if !ok {
		t.Fatalf("LoadPosixUsername() ok = false, want true")
	}
	if got != "user000042" {
		t.Errorf("LoadPosixUsername() = %q, want %q", got, "user000042")
	}
}

// Requirement: CL-F-06
func TestLoadPosixUsername_NotYetSaved(t *testing.T) {
	dir := t.TempDir()

	got, ok, err := LoadPosixUsername(dir)
	if err != nil {
		t.Fatalf("LoadPosixUsername() error = %v, want nil", err)
	}
	if ok {
		t.Errorf("LoadPosixUsername() ok = true, want false when nothing was saved")
	}
	if got != "" {
		t.Errorf("LoadPosixUsername() = %q, want empty string", got)
	}
}

// Requirement: CL-F-06
func TestSavePosixUsername_Overwrites(t *testing.T) {
	dir := t.TempDir()

	if err := SavePosixUsername(dir, "user000001"); err != nil {
		t.Fatalf("SavePosixUsername() error = %v, want nil", err)
	}
	if err := SavePosixUsername(dir, "user000002"); err != nil {
		t.Fatalf("SavePosixUsername() error = %v, want nil", err)
	}

	got, _, err := LoadPosixUsername(dir)
	if err != nil {
		t.Fatalf("LoadPosixUsername() error = %v, want nil", err)
	}
	if got != "user000002" {
		t.Errorf("LoadPosixUsername() = %q, want %q (overwritten value)", got, "user000002")
	}
}
