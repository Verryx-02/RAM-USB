package restic

import (
	"context"
	"errors"
	"testing"

	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
)

func testConfig(fake execrunner.Runner) Config {
	return Config{
		Runner:             fake,
		Host:               "storage-service.mesh.ts.net",
		PosixUsername:      "user000001",
		PrivateKeyPath:     "/home/user/.config/ram-usb/id_ed25519",
		RepositoryPassword: "repo-secret",
	}
}

// Requirement: CL-F-06
func TestInit_Success(t *testing.T) {
	fake := &execrunner.Fake{Output: []byte("created restic repository")}
	c := testConfig(fake)

	if err := Init(context.Background(), c); err != nil {
		t.Fatalf("Init() error = %v, want nil", err)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("fake.Calls = %v, want exactly one call", fake.Calls)
	}
	call := fake.Calls[0]
	wantRepo := "sftp:user000001@storage-service.mesh.ts.net:/data"
	wantSftpCmd := "sftp.command=ssh -i /home/user/.config/ram-usb/id_ed25519 -l user000001 storage-service.mesh.ts.net -s sftp"
	want := []string{"restic", "-r", wantRepo, "-o", wantSftpCmd, "init"}
	if len(call) != len(want) {
		t.Fatalf("call = %v, want %v", call, want)
	}
	for i := range want {
		if call[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, call[i], want[i])
		}
	}
}

// Requirement: CL-F-06
func TestInit_AlreadyInitialized_IsNotAnError(t *testing.T) {
	fake := &execrunner.Fake{
		Output: []byte("config file already exists, quitting: repository master key and config already initialized"),
		Err:    errors.New("exit status 1"),
	}
	c := testConfig(fake)

	if err := Init(context.Background(), c); err != nil {
		t.Errorf("Init() error = %v, want nil for an already-initialized repository", err)
	}
}

// Requirement: CL-F-06
func TestInit_GenuineFailure(t *testing.T) {
	fake := &execrunner.Fake{
		Output: []byte("Fatal: unable to open config file: connection refused"),
		Err:    errors.New("exit status 1"),
	}
	c := testConfig(fake)

	err := Init(context.Background(), c)
	if !errors.Is(err, ErrRepositoryOperationFailed) {
		t.Errorf("Init() error = %v, want ErrRepositoryOperationFailed", err)
	}
}

// Requirement: CL-F-06
func TestBackup_Success(t *testing.T) {
	fake := &execrunner.Fake{Output: []byte("snapshot abc123 saved")}
	c := testConfig(fake)

	if err := Backup(context.Background(), c, "/Users/alice/Documents"); err != nil {
		t.Fatalf("Backup() error = %v, want nil", err)
	}

	call := fake.Calls[0]
	if call[len(call)-2] != "backup" || call[len(call)-1] != "/Users/alice/Documents" {
		t.Errorf("call = %v, want it to end with [backup /Users/alice/Documents]", call)
	}
}

// Requirement: CL-F-06
func TestBackup_RejectsEmptyPath(t *testing.T) {
	fake := &execrunner.Fake{}
	c := testConfig(fake)

	if err := Backup(context.Background(), c, ""); err == nil {
		t.Errorf("Backup() error = nil, want non-nil for an empty localPath")
	}
	if len(fake.Calls) != 0 {
		t.Errorf("Backup() invoked restic despite an invalid argument: %v", fake.Calls)
	}
}

// Requirement: CL-F-06
func TestBackup_Failure(t *testing.T) {
	fake := &execrunner.Fake{Output: []byte("Fatal: unable to save snapshot"), Err: errors.New("exit status 1")}
	c := testConfig(fake)

	err := Backup(context.Background(), c, "/path")
	if !errors.Is(err, ErrRepositoryOperationFailed) {
		t.Errorf("Backup() error = %v, want ErrRepositoryOperationFailed", err)
	}
}

// Requirement: CL-F-07
func TestRestore_Success(t *testing.T) {
	fake := &execrunner.Fake{Output: []byte("restoring <Snapshot abc123> to /target")}
	c := testConfig(fake)

	if err := Restore(context.Background(), c, "latest", "/Users/alice/Restore"); err != nil {
		t.Fatalf("Restore() error = %v, want nil", err)
	}

	call := fake.Calls[0]
	wantTail := []string{"restore", "latest", "--target", "/Users/alice/Restore"}
	got := call[len(call)-len(wantTail):]
	for i := range wantTail {
		if got[i] != wantTail[i] {
			t.Errorf("call tail = %v, want %v", got, wantTail)
			break
		}
	}
}

// Requirement: CL-F-07
func TestRestore_RejectsEmptyArguments(t *testing.T) {
	tests := []struct {
		name       string
		snapshotID string
		targetPath string
	}{
		{name: "empty snapshot id", snapshotID: "", targetPath: "/target"},
		{name: "empty target path", snapshotID: "latest", targetPath: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &execrunner.Fake{}
			c := testConfig(fake)
			if err := Restore(context.Background(), c, tt.snapshotID, tt.targetPath); err == nil {
				t.Errorf("Restore() error = nil, want non-nil")
			}
			if len(fake.Calls) != 0 {
				t.Errorf("Restore() invoked restic despite an invalid argument: %v", fake.Calls)
			}
		})
	}
}

// Requirement: CL-F-06/CL-F-07
func TestEnv_CarriesRepositoryPasswordNotArguments(t *testing.T) {
	fake := &execrunner.Fake{}
	c := testConfig(fake)

	env := c.env()
	if len(env) != 1 || env[0] != "RESTIC_PASSWORD=repo-secret" {
		t.Errorf("env() = %v, want [RESTIC_PASSWORD=repo-secret]", env)
	}
}
