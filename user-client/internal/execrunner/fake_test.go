package execrunner

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Requirement: CL-F-06 (Fake is the shared subprocess test double used by
// mesh's and restic's own CL-F-04/05/06/07 tests; this test only verifies
// the double's own bookkeeping)
func TestFake_RecordsCallsAndDefaultOutput(t *testing.T) {
	f := &Fake{Output: []byte("default"), Err: nil}

	out, err := f.Run(context.Background(), nil, "restic", "init")
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if string(out) != "default" {
		t.Errorf("Run() output = %q, want %q", out, "default")
	}

	want := [][]string{{"restic", "init"}}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Errorf("f.Calls = %v, want %v", f.Calls, want)
	}
}

// Requirement: CL-F-06
func TestFake_PerCallOverrides(t *testing.T) {
	wantErr := errors.New("boom")
	f := &Fake{
		Output:    []byte("default"),
		OutputFor: map[string][]byte{"restic backup /path": []byte("snapshot saved")},
		ErrFor:    map[string]error{"restic init": wantErr},
	}

	if _, err := f.Run(context.Background(), nil, "restic", "init"); !errors.Is(err, wantErr) {
		t.Errorf("Run(init) error = %v, want %v", err, wantErr)
	}

	out, err := f.Run(context.Background(), nil, "restic", "backup", "/path")
	if err != nil {
		t.Fatalf("Run(backup) error = %v, want nil", err)
	}
	if string(out) != "snapshot saved" {
		t.Errorf("Run(backup) output = %q, want %q", out, "snapshot saved")
	}
}
