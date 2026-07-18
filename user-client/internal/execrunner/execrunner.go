// Package execrunner provides the single injectable seam every package
// that shells out to an external binary (mesh's "tailscale", restic's
// "restic") depends on, instead of calling os/exec directly. This is a
// design choice not specified by the SRS: CL-F-04/CL-F-05/CL-F-06/CL-F-07
// all require driving a real, separately-installed system binary, but a
// unit test (docs/Test_Plan.md §2.1: "no network, no other service") must
// not actually invoke tailscale/restic - so every caller depends on the
// Runner interface below, and tests substitute a hand-written fake
// (CONTRIBUTING.md §7.5's "hand-written fakes implementing the relevant
// interface"), never a real subprocess.
package execrunner

import (
	"context"
	"os/exec"
)

// Runner runs an external command and returns its combined stdout+stderr
// output. The combined stream (rather than separate stdout/stderr) is
// sufficient for this project's needs: every caller either succeeds and
// ignores the output, or fails and logs/display the combined output as
// the one diagnostic string it has, mirroring how a user would read the
// same command's output at a terminal.
//
// env holds extra "KEY=VALUE" entries added to the child process's
// environment in addition to the current process's own environment (e.g.
// restic's RESTIC_PASSWORD, CL-F-06/CL-F-07) - nil when a caller (e.g.
// mesh's tailscale invocation, CL-F-04) needs no extra environment beyond
// its command-line flags.
type Runner interface {
	Run(ctx context.Context, env []string, name string, args ...string) (output []byte, err error)
}

// Real is the production Runner: it shells out to the named binary via
// os/exec, exactly as CL-F-04/CL-F-05 (tailscale) and CL-F-06/CL-F-07
// (restic) require.
type Real struct{}

// Run implements Runner by invoking os/exec.CommandContext. gosec's G204
// ("subprocess launched with variable") is expected here and cannot be
// eliminated by construction: this package's entire purpose (CL-F-04's
// tailscale, CL-F-06/CL-F-07's restic) is to run an externally-installed
// binary chosen by its caller - name/args are supplied by this project's
// own mesh/restic packages, never by unsanitized end-user input passed
// straight through, so the flagged pattern is this package's intended
// design, not an oversight.
func (Real) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name/args come from this project's own mesh/restic packages, not raw user input; shelling out to an externally-installed binary is this package's entire purpose (CL-F-04/CL-F-06/CL-F-07).
	if env != nil {
		cmd.Env = append(cmd.Environ(), env...)
	}
	return cmd.CombinedOutput()
}
