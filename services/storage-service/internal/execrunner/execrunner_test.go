package execrunner

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// Requirement: ST-F-06 (Real is the shared subprocess seam ST-F-06/ST-F-08
// depend on for invoking useradd; this test exercises Real directly, not
// any specific business logic, using a harmless stdlib-adjacent binary
// rather than useradd).
func TestReal_Run(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell being present")
	}

	r := Real{}
	out, err := r.Run(context.Background(), "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("Run() output = %q, want %q", got, "hello")
	}
}

// Requirement: ST-F-06
func TestReal_Run_NonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell being present")
	}

	r := Real{}
	_, err := r.Run(context.Background(), "sh", "-c", "exit 1")
	if err == nil {
		t.Errorf("Run() error = nil, want non-nil for a non-zero exit")
	}
}

// Requirement: ST-F-06
func TestFake_Run_RecordsCall(t *testing.T) {
	f := &Fake{Output: []byte("fake output")}

	out, err := f.Run(context.Background(), "useradd", "--no-create-home", "user123abc")
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if string(out) != "fake output" {
		t.Errorf("Run() output = %q, want %q", out, "fake output")
	}

	if len(f.Calls) != 1 {
		t.Fatalf("len(Calls) = %d, want 1", len(f.Calls))
	}
	got := f.Calls[0]
	if got.Name != "useradd" {
		t.Errorf("Calls[0].Name = %q, want %q", got.Name, "useradd")
	}
	wantArgs := []string{"--no-create-home", "user123abc"}
	if len(got.Args) != len(wantArgs) {
		t.Fatalf("Calls[0].Args = %v, want %v", got.Args, wantArgs)
	}
	for i, a := range wantArgs {
		if got.Args[i] != a {
			t.Errorf("Calls[0].Args[%d] = %q, want %q", i, got.Args[i], a)
		}
	}
}
