// Package restic implements CL-F-06 (restic backup) and CL-F-07 (restic
// restore) against Storage-Service over SFTP, by shelling out to a
// separately-installed "restic" binary via execrunner.Runner. restic has
// no embeddable Go library - its own source keeps everything under
// internal/, unimportable by any other module (restic maintainers' own
// stated position, confirmed by inspection this session) - so an external
// process is the only integration route.
//
// Authentication uses the SSH private key CL-F-01 generated, never the
// user's default ~/.ssh key: restic's own "-o sftp.command" option
// overrides the ssh invocation it uses internally.
//
// Per UC-03/UC-04, the data restic backs up is already encrypted
// client-side by the time it reaches Storage-Service - restic's own
// backup format is itself always encrypted at rest (a restic repository
// cannot be created without a repository password), which is what
// satisfies RNF-SEC-01's zero-knowledge guarantee for backup content; this
// package adds no separate encryption layer of its own.
package restic

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
)

// Config holds everything one restic invocation needs: which binary to
// run (via Runner), which repository to address, and how to authenticate.
type Config struct {
	// Runner executes the restic binary (and, transitively, the ssh
	// binary restic's own sftp.command spawns).
	Runner execrunner.Runner

	// Host is the Storage-Service hostname to connect to - resolved via
	// MagicDNS (CL-F-05) once the mesh has been joined (CL-F-04), e.g.
	// "storage-service" or "storage-service.mesh-name.ts.net".
	Host string

	// PosixUsername is the per-user POSIX account Storage-Service created
	// at registration (DV-F-08/ST-F-06), and the chroot this repository
	// lives inside (SRS §4.5: /storage/user<xxxxxx>/data/).
	PosixUsername string

	// PrivateKeyPath is the path to the SSH private key CL-F-01 generated
	// - restic authenticates as PosixUsername using this key, never the
	// user's own default SSH identity.
	PrivateKeyPath string

	// RepositoryPassword is restic's own repository-encryption password,
	// distinct from the user's RAM-USB login password (see this
	// package's own doc note on where this value comes from - flagged as
	// a design decision the SRS does not specify, see internal/reposecret).
	RepositoryPassword string
}

// ErrRepositoryOperationFailed wraps a restic invocation's combined output
// on a non-zero exit, other than the specific "already initialized" case
// Init handles gracefully.
var ErrRepositoryOperationFailed = errors.New("restic: operation failed")

// alreadyInitializedMarker is the substring restic's own stderr contains
// when "restic init" is run against a repository that already exists -
// confirmed against restic's own CLI output, used to distinguish this
// expected, non-error case (Init is safe to call on every backup, not
// just the first) from a genuine failure.
const alreadyInitializedMarker = "already initialized"

// repository returns the sftp: repository URL this Config addresses -
// the user's writable data/ subdirectory inside their own chroot (ST-F-06/
// ST-F-08, SRS §4.5).
func (c Config) repository() string {
	return fmt.Sprintf("sftp:%s@%s:/data", c.PosixUsername, c.Host)
}

// sftpCommand returns the -o sftp.command value that makes restic
// authenticate over SFTP using CL-F-01's client-generated private key
// instead of any default identity.
func (c Config) sftpCommand() string {
	return fmt.Sprintf("ssh -i %s -l %s %s -s sftp", c.PrivateKeyPath, c.PosixUsername, c.Host)
}

// env returns the RESTIC_PASSWORD environment entry every invocation
// needs - restic itself refuses to run without a repository password
// available by some means, and this project supplies it via environment
// variable (see this package's doc comment on RepositoryPassword).
func (c Config) env() []string {
	return []string{"RESTIC_PASSWORD=" + c.RepositoryPassword}
}

// run invokes restic with the repository/sftp.command flags common to
// every operation, followed by extraArgs.
func (c Config) run(ctx context.Context, extraArgs ...string) ([]byte, error) {
	args := append([]string{
		"-r", c.repository(),
		"-o", "sftp.command=" + c.sftpCommand(),
	}, extraArgs...)
	return c.Runner.Run(ctx, c.env(), "restic", args...)
}

// Init runs "restic init" against c's repository. A repository that is
// already initialized (every backup after the first) is treated as
// success, not an error - CL-F-06 needs Init to be safely callable before
// every backup, not just once ever.
func Init(ctx context.Context, c Config) error {
	output, err := c.run(ctx, "init")
	if err != nil {
		if strings.Contains(string(output), alreadyInitializedMarker) {
			return nil
		}
		return fmt.Errorf("%w: init: %s", ErrRepositoryOperationFailed, output)
	}
	return nil
}

// Backup implements CL-F-06: runs "restic backup localPath" against c's
// repository, authenticating over SFTP with CL-F-01's client-generated
// private key.
func Backup(ctx context.Context, c Config, localPath string) error {
	if localPath == "" {
		return fmt.Errorf("restic: localPath must not be empty")
	}
	output, err := c.run(ctx, "backup", localPath)
	if err != nil {
		return fmt.Errorf("%w: backup: %s", ErrRepositoryOperationFailed, output)
	}
	return nil
}

// Restore implements CL-F-07: runs "restic restore snapshotID --target
// targetPath" against c's repository, using the same SFTP authentication
// method as Backup. snapshotID may be the literal string "latest".
func Restore(ctx context.Context, c Config, snapshotID, targetPath string) error {
	if snapshotID == "" {
		return fmt.Errorf("restic: snapshotID must not be empty")
	}
	if targetPath == "" {
		return fmt.Errorf("restic: targetPath must not be empty")
	}
	output, err := c.run(ctx, "restore", snapshotID, "--target", targetPath)
	if err != nil {
		return fmt.Errorf("%w: restore: %s", ErrRepositoryOperationFailed, output)
	}
	return nil
}
