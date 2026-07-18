package execrunner

import "context"

// Fake is a hand-written test double for Runner (CONTRIBUTING.md §7.5), not
// a mocking library. It records every call it received and returns the
// caller-configured Output/Err (or, if RunFunc is set, whatever RunFunc
// computes for that specific call), so tests can assert on exactly what
// command(s) a package under test attempted to run without spawning a real
// subprocess.
type Fake struct {
	// Output and Err are returned by every call to Run, unless RunFunc is
	// set.
	Output []byte
	Err    error

	// RunFunc, if non-nil, is called instead of returning the fixed
	// Output/Err above - needed when a test's package under it makes more
	// than one Run call in sequence and different calls must behave
	// differently (e.g. posixuser.Creator's groupadd succeeding followed
	// by useradd failing, to exercise its rollback path).
	RunFunc func(name string, args ...string) ([]byte, error)

	// Calls records every invocation, in order, so a test can assert both
	// that a call happened and its exact arguments.
	Calls []FakeCall
}

// FakeCall is one recorded invocation of Fake.Run.
type FakeCall struct {
	Name string
	Args []string
}

// Run implements Runner by recording the call and returning either
// RunFunc's result (if set) or the caller-configured Output/Err.
func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, FakeCall{Name: name, Args: args})
	if f.RunFunc != nil {
		return f.RunFunc(name, args...)
	}
	return f.Output, f.Err
}
