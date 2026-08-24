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
	// lives inside (SRS section 4.5: /storage/user<xxxxxx>/data/).
	PosixUsername string

	// PrivateKeyPath is the path to the SSH private key CL-F-01 generated
	// - restic authenticates as PosixUsername using this key, never the
	// user's own default SSH identity.
	PrivateKeyPath string

	// KnownHostsPath is the path to a known_hosts file (written by
	// WriteKnownHosts) pinning Storage-Service's SSH host key (CL-F-11,
	// ST-F-16). ssh is pointed at this file with strict host-key checking
	// on, so a host key that changes at connection time aborts the
	// connection rather than prompting or silently accepting it
	// (trust-on-first-use is explicitly not used - CL-F-11).
	KnownHostsPath string

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

// SSHPort is the fixed TCP port Storage-Service's sshd listens on
// (ST-F-03) - CAP_NET_BIND_SERVICE is deliberately outside the container's
// capability set, so the default port 22 is not bindable at all, and
// every connection must name this port explicitly.
const SSHPort = 2222

// repository returns the sftp: repository URL this Config addresses -
// the user's writable data/ subdirectory inside their own chroot (ST-F-06/
// ST-F-08, SRS section 4.5).
func (c Config) repository() string {
	return fmt.Sprintf("sftp:%s@%s:/data", c.PosixUsername, c.Host)
}

// sftpCommand returns the -o sftp.command value that makes restic
// authenticate over SFTP using CL-F-01's client-generated private key
// instead of any default identity, on Storage-Service's SSHPort (ST-F-03),
// with the host key pinned at KnownHostsPath and strict checking on
// (CL-F-11).
//
// Every interpolated value is single-quoted, and each -o option's whole
// "key=value" pair is quoted as one token rather than quoting only the
// value: restic splits sftp.command shell-style before exec'ing it, but
// (confirmed empirically against restic 0.19.0's actual splitter, not just
// assumed) it only treats a quote as opening a token when the quote is the
// token's first character. -o UserKnownHostsFile='%s' puts the quote after
// the "=", so restic's splitter hands ssh a bare "UserKnownHostsFile=" and
// the path as a second, unrelated argument - ssh then rejects the option
// with "no argument after keyword" and the sftp subsystem never starts.
// Quoting the entire "-o 'UserKnownHostsFile=...'" token sidesteps this
// because the quote is then the token's first character. The same
// sshkey.ConfigDir() space-containing path (darwin: "$HOME/Library/
// Application Support/ram-usb") motivates the quoting itself.
func (c Config) sftpCommand() string {
	return fmt.Sprintf(
		"ssh -i '%s' -o 'UserKnownHostsFile=%s' -o StrictHostKeyChecking=yes -p %d -l '%s' '%s' -s sftp",
		c.PrivateKeyPath, c.KnownHostsPath, SSHPort, c.PosixUsername, c.Host,
	)
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
