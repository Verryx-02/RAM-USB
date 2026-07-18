package execrunner

import (
	"context"
	"strings"
)

// Fake is a hand-written Runner double (CONTRIBUTING.md §7.5: "hand-written
// fakes implementing the relevant interface", not a mocking framework),
// exported (not confined to a _test.go file) so mesh's and restic's own
// tests can construct one directly, the same precedent as pkg/mtls.TestCA
// living in its own package rather than a separate test-only package.
type Fake struct {
	// Calls records every invocation, in order, as "name arg1 arg2 ...".
	Calls [][]string
	// Output is returned by every call, unless a matching entry exists in
	// OutputFor.
	Output []byte
	// Err is returned by every call, unless a matching entry exists in
	// ErrFor.
	Err error
	// OutputFor and ErrFor, keyed by the joined "name arg1 arg2 ..."
	// string, override Output/Err for a specific invocation.
	OutputFor map[string][]byte
	ErrFor    map[string]error
}

// Run implements Runner without spawning any real process. env is
// recorded neither in Calls nor used to select an OutputFor/ErrFor
// override - tests that care about the environment passed to a call
// should assert on it separately if a future need arises; today's callers
// (mesh, restic) only need to assert on the command name/arguments.
func (f *Fake) Run(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.Calls = append(f.Calls, call)
	key := strings.Join(call, " ")

	if f.ErrFor != nil {
		if err, ok := f.ErrFor[key]; ok {
			return f.OutputFor[key], err
		}
	}
	if f.OutputFor != nil {
		if out, ok := f.OutputFor[key]; ok {
			return out, nil
		}
	}
	return f.Output, f.Err
}
