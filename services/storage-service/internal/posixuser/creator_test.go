package posixuser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/execrunner"
)

// fakeDirMaker is a hand-written test double for DirMaker (CONTRIBUTING.md
// §7.5), recording every call in order (including the requested mode, so
// tests can assert the chroot root and data directory get two different,
// correct modes) so tests can assert both that a call happened and its
// exact order relative to other calls.
type fakeDirMaker struct {
	mkdirErr error
	chownErr error
	calls    []string
}

func (f *fakeDirMaker) Mkdir(path string, mode os.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("mkdir:%s:%04o", path, mode))
	return f.mkdirErr
}

func (f *fakeDirMaker) Chown(path, username string) error {
	f.calls = append(f.calls, "chown:"+path+":"+username)
	return f.chownErr
}

// mkdirFailDirMaker fails only on a specific path, to test that a later
// directory-creation failure still returns an error without swallowing it.
type selectiveFailDirMaker struct {
	failOnPath string
	calls      []string
}

func (f *selectiveFailDirMaker) Mkdir(path string, mode os.FileMode) error {
	f.calls = append(f.calls, fmt.Sprintf("mkdir:%s:%04o", path, mode))
	if path == f.failOnPath {
		return errors.New("mkdir failed")
	}
	return nil
}

func (f *selectiveFailDirMaker) Chown(path, username string) error {
	f.calls = append(f.calls, "chown:"+path+":"+username)
	return nil
}

// Requirement: ST-F-06
func TestCreator_CreateUser_Success(t *testing.T) {
	runner := &execrunner.Fake{}
	dm := &fakeDirMaker{}
	c := &Creator{Runner: runner, DirMaker: dm}

	username := "user7k2m9x"
	if err := c.CreateUser(context.Background(), username); err != nil {
		t.Fatalf("CreateUser() error = %v, want nil", err)
	}

	if len(runner.Calls) != 2 {
		t.Fatalf("len(runner.Calls) = %d, want 2 (groupadd then useradd)", len(runner.Calls))
	}

	groupaddCall := runner.Calls[0]
	if groupaddCall.Name != "groupadd" {
		t.Errorf("Calls[0].Name = %q, want %q", groupaddCall.Name, "groupadd")
	}
	wantGroupaddArgs := []string{username}
	if len(groupaddCall.Args) != len(wantGroupaddArgs) {
		t.Fatalf("groupadd args = %v, want %v", groupaddCall.Args, wantGroupaddArgs)
	}
	for i, a := range wantGroupaddArgs {
		if groupaddCall.Args[i] != a {
			t.Errorf("groupadd args[%d] = %q, want %q", i, groupaddCall.Args[i], a)
		}
	}

	useraddCall := runner.Calls[1]
	if useraddCall.Name != "useradd" {
		t.Errorf("Calls[1].Name = %q, want %q", useraddCall.Name, "useradd")
	}
	wantUseraddArgs := []string{
		"--no-create-home",
		"--home-dir", "/storage/" + username,
		"--shell", "/usr/sbin/nologin",
		"--gid", username,
		"--password", "*",
		username,
	}
	if len(useraddCall.Args) != len(wantUseraddArgs) {
		t.Fatalf("useradd args = %v, want %v", useraddCall.Args, wantUseraddArgs)
	}
	for i, a := range wantUseraddArgs {
		if useraddCall.Args[i] != a {
			t.Errorf("useradd args[%d] = %q, want %q", i, useraddCall.Args[i], a)
		}
	}

	wantDirCalls := []string{
		fmt.Sprintf("mkdir:/storage/%s:%04o", username, chrootRootMode),
		"chown:/storage/" + username + ":root",
		fmt.Sprintf("mkdir:/storage/%s/data:%04o", username, dataDirMode),
		"chown:/storage/" + username + "/data:" + username,
	}
	if len(dm.calls) != len(wantDirCalls) {
		t.Fatalf("dm.calls = %v, want %v", dm.calls, wantDirCalls)
	}
	for i, c := range wantDirCalls {
		if dm.calls[i] != c {
			t.Errorf("dm.calls[%d] = %q, want %q", i, dm.calls[i], c)
		}
	}
}

// Requirement: ST-F-06
func TestCreator_CreateUser_GroupaddFailure(t *testing.T) {
	runner := &execrunner.Fake{Err: errors.New("groupadd: exit status 1")}
	dm := &fakeDirMaker{}
	c := &Creator{Runner: runner, DirMaker: dm}

	err := c.CreateUser(context.Background(), "user7k2m9x")
	if err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil")
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("runner.Calls = %v, want exactly 1 (useradd must never run after a groupadd failure)", runner.Calls)
	}
	if runner.Calls[0].Name != "groupadd" {
		t.Errorf("runner.Calls[0].Name = %q, want %q", runner.Calls[0].Name, "groupadd")
	}
	if len(dm.calls) != 0 {
		t.Errorf("dm.calls = %v, want none (groupadd failure must short-circuit)", dm.calls)
	}
}

// Requirement: ST-F-06
func TestCreator_CreateUser_UseraddFailure_RollsBackGroup(t *testing.T) {
	username := "user7k2m9x"
	runner := &execrunner.Fake{
		RunFunc: func(name string, _ ...string) ([]byte, error) {
			if name == "useradd" {
				return nil, errors.New("useradd: exit status 1")
			}
			return nil, nil
		},
	}
	dm := &fakeDirMaker{}
	c := &Creator{Runner: runner, DirMaker: dm}

	err := c.CreateUser(context.Background(), username)
	if err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil")
	}
	if len(dm.calls) != 0 {
		t.Errorf("dm.calls = %v, want none (useradd failure must short-circuit before any directory work)", dm.calls)
	}

	if len(runner.Calls) != 3 {
		t.Fatalf("runner.Calls = %v, want exactly 3 (groupadd, useradd, groupdel rollback)", runner.Calls)
	}
	if runner.Calls[0].Name != "groupadd" {
		t.Errorf("runner.Calls[0].Name = %q, want %q", runner.Calls[0].Name, "groupadd")
	}
	if runner.Calls[1].Name != "useradd" {
		t.Errorf("runner.Calls[1].Name = %q, want %q", runner.Calls[1].Name, "useradd")
	}
	rollbackCall := runner.Calls[2]
	if rollbackCall.Name != "groupdel" {
		t.Errorf("runner.Calls[2].Name = %q, want %q (rollback of the orphaned group)", rollbackCall.Name, "groupdel")
	}
	wantRollbackArgs := []string{username}
	if len(rollbackCall.Args) != len(wantRollbackArgs) || rollbackCall.Args[0] != username {
		t.Errorf("groupdel args = %v, want %v", rollbackCall.Args, wantRollbackArgs)
	}
}

// Requirement: ST-F-06
func TestCreator_CreateUser_UseraddFailure_RollbackGroupdelAlsoFails(t *testing.T) {
	// Even if the rollback groupdel itself fails, CreateUser must still
	// report the original useradd failure, not mask it with a secondary
	// cleanup error.
	username := "user7k2m9x"
	runner := &execrunner.Fake{
		RunFunc: func(name string, _ ...string) ([]byte, error) {
			switch name {
			case "useradd":
				return nil, errors.New("useradd: exit status 1")
			case "groupdel":
				return nil, errors.New("groupdel: exit status 1")
			default:
				return nil, nil
			}
		},
	}
	dm := &fakeDirMaker{}
	c := &Creator{Runner: runner, DirMaker: dm}

	err := c.CreateUser(context.Background(), username)
	if err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil")
	}
	if !errors.Is(err, ErrUseraddFailed) {
		t.Errorf("CreateUser() error = %v, want it to wrap ErrUseraddFailed (the rollback failure must not mask the original one)", err)
	}
	if len(runner.Calls) != 3 {
		t.Fatalf("runner.Calls = %v, want exactly 3 (groupadd, useradd, groupdel rollback attempt)", runner.Calls)
	}
}

// Requirement: ST-F-06
func TestCreator_CreateUser_UseraddAlreadyExists(t *testing.T) {
	runner := &execrunner.Fake{
		RunFunc: func(name string, _ ...string) ([]byte, error) {
			if name == "useradd" {
				return []byte("useradd: user 'user7k2m9x' already exists"), errors.New("exit status 9")
			}
			return nil, nil
		},
	}
	dm := &fakeDirMaker{}
	c := &Creator{Runner: runner, DirMaker: dm}

	err := c.CreateUser(context.Background(), "user7k2m9x")
	if err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil for an already-existing user")
	}
	if len(dm.calls) != 0 {
		t.Errorf("dm.calls = %v, want none (already-exists must short-circuit)", dm.calls)
	}
}

// Requirement: ST-F-08
func TestCreator_CreateUser_MalformedUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{"too short", "user123"},
		{"too long", "user1234567"},
		{"uppercase", "userABC123"},
		{"missing prefix", "xser123456"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &execrunner.Fake{}
			dm := &fakeDirMaker{}
			c := &Creator{Runner: runner, DirMaker: dm}

			err := c.CreateUser(context.Background(), tt.username)
			if err == nil {
				t.Fatal("CreateUser() error = nil, want non-nil for malformed username")
			}
			if len(runner.Calls) != 0 {
				t.Errorf("runner.Calls = %v, want none", runner.Calls)
			}
			if len(dm.calls) != 0 {
				t.Errorf("dm.calls = %v, want none", dm.calls)
			}
		})
	}
}

// Requirement: ST-F-08
func TestCreator_CreateUser_DirectoryCreationFailureAfterUseradd(t *testing.T) {
	runner := &execrunner.Fake{}
	username := "user7k2m9x"
	dm := &selectiveFailDirMaker{failOnPath: "/storage/" + username + "/data"}
	c := &Creator{Runner: runner, DirMaker: dm}

	err := c.CreateUser(context.Background(), username)
	if err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil when directory creation fails")
	}
	if len(runner.Calls) != 2 {
		t.Errorf("runner.Calls = %v, want exactly 2 (groupadd and useradd both still ran)", runner.Calls)
	}
}
