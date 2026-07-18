package execrunner

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

// Requirement: CL-F-06 (Real is the shared subprocess seam CL-F-04/05/06/07
// all depend on; this test exercises Real directly, not any specific
// requirement's business logic, using a harmless stdlib-adjacent binary
// rather than tailscale/restic).
func TestReal_Run(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell being present")
	}

	r := Real{}
	out, err := r.Run(context.Background(), nil, "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("Run() output = %q, want %q", got, "hello")
	}
}

// Requirement: CL-F-06
func TestReal_Run_PassesEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell being present")
	}

	r := Real{}
	out, err := r.Run(context.Background(), []string{"RAM_USB_TEST_VAR=set-by-runner"}, "sh", "-c", "echo $RAM_USB_TEST_VAR")
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := strings.TrimSpace(string(out)); got != "set-by-runner" {
		t.Errorf("Run() output = %q, want %q", got, "set-by-runner")
	}
}

// Requirement: CL-F-06
func TestReal_Run_NonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX shell being present")
	}

	r := Real{}
	_, err := r.Run(context.Background(), nil, "sh", "-c", "exit 1")
	if err == nil {
		t.Errorf("Run() error = nil, want non-nil for a non-zero exit")
	}
}
