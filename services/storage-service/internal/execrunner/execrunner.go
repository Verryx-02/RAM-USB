// Package execrunner provides the single injectable seam Storage-Service's
// POSIX-user-creation code (ST-F-06, ST-F-08) depends on for shelling out to
// external binaries (useradd), instead of calling os/exec directly. This is
// a design choice not specified by the SRS: a unit test (docs/Test_Plan.md
// §2.1: "no network, no other service") must not actually invoke useradd -
// so every caller depends on the Runner interface below, and tests
// substitute a hand-written fake (CONTRIBUTING.md §7.5's "hand-written
// fakes implementing the relevant interface"), never a real subprocess.
//
// This package deliberately duplicates
// user-client/internal/execrunner's shape (Runner/Real/Fake) rather than
// importing it: Go's internal-package import rule means a package under
// .../user-client/internal/... is only importable by code rooted at
// .../user-client/, and user-client is a separate module from this
// project's services in the first place. Any future change to this shape
// must be made on both sides by hand; there is no shared type to change
// once. Same pattern already documented for
// services/storage-service/internal/httpapi's JSON contract with
// database-vault/internal/posix.
package execrunner

import (
	"context"
	"os/exec"
)

// Runner runs an external command and returns its combined stdout+stderr
// output. The combined stream (rather than separate stdout/stderr) is
// sufficient for this project's needs: every caller either succeeds and
// ignores the output, or fails and logs the combined output as the one
// diagnostic string it has, mirroring how an operator would read the same
// command's output at a terminal.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (output []byte, err error)
}

// Real is the production Runner: it shells out to the named binary via
// os/exec, exactly as ST-F-06/ST-F-08 (useradd) require.
type Real struct{}

// Run implements Runner by invoking os/exec.CommandContext. gosec's G204
// ("subprocess launched with variable") is expected here and cannot be
// eliminated by construction: this package's entire purpose (ST-F-06's
// useradd invocation) is to run a system binary with arguments chosen by
// its caller - name/args are supplied by this project's own posixuser
// package, built entirely from a single re-validated username, never from
// raw untrusted input passed straight through, so the flagged pattern is
// this package's intended design, not an oversight.
func (Real) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name/args come from this project's own posixuser package, built from a single re-validated username, not raw user input; shelling out to a system binary (useradd) is this package's entire purpose (ST-F-06/ST-F-08).
	return cmd.CombinedOutput()
}
