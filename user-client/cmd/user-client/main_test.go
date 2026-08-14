package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/user-client/internal/clientstate"
	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
	"github.com/Verryx-02/RAM-USB/user-client/internal/mesh"
	"github.com/Verryx-02/RAM-USB/user-client/internal/restic"
	"github.com/Verryx-02/RAM-USB/user-client/internal/sshkey"
)

const validPassword = "Str0ng!Pass"

// isolateConfigDir points sshkey.ConfigDir (and therefore every
// clientstate/reposecret helper keyed off the same directory) at a fresh
// temporary directory for the duration of a test, so a test run never
// touches the real invoking user's actual RAM-USB config directory.
// os.UserConfigDir() consults XDG_CONFIG_HOME on Linux (falling back to
// $HOME/.config) and $HOME/Library/Application Support on macOS - setting
// both env vars covers either platform this suite might run on.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
}

// setupConfigDir redirects sshkey.ConfigDir() (and, transitively,
// clientstate/reposecret's own os.UserConfigDir()-based storage) to a
// fresh temporary directory for the duration of one test, so a test never
// touches the real invoking user's ~/.config/ram-usb (or macOS
// equivalent). Setting XDG_CONFIG_HOME to the empty string forces Linux's
// os.UserConfigDir() fallback path (HOME + "/.config") instead of
// inheriting whatever XDG_CONFIG_HOME the test host happens to have set.
func setupConfigDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", "")

	dir, err := sshkey.ConfigDir()
	if err != nil {
		t.Fatalf("sshkey.ConfigDir() error = %v, want nil", err)
	}
	return dir
}

// setupRegisteredClient additionally seeds dir with a real key pair
// (CL-F-01) and a persisted POSIX username (as a prior "register" run
// would have left behind), the local state runBackup/runRestore's own
// resticConfig requires before backing up or restoring.
func setupRegisteredClient(t *testing.T) (dir, posixUsername string) {
	t.Helper()
	dir = setupConfigDir(t)
	if _, err := sshkey.EnsureKeyPair(dir); err != nil {
		t.Fatalf("sshkey.EnsureKeyPair() error = %v, want nil", err)
	}
	posixUsername = "user000001"
	if err := clientstate.SavePosixUsername(dir, posixUsername); err != nil {
		t.Fatalf("clientstate.SavePosixUsername() error = %v, want nil", err)
	}
	return dir, posixUsername
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. usage() has no return value and writes
// directly to the package-level os.Stderr, so this is the only way to
// assert on its output.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(out)
}

// Requirement: CL-F-08
func TestUsage(t *testing.T) {
	out := captureStderr(t, usage)
	if out == "" {
		t.Fatal("usage() wrote nothing to stderr")
	}
	const want = "usage: user-client <register|login|backup|restore> [flags]\n"
	if out != want {
		t.Errorf("usage() wrote %q, want %q", out, want)
	}
}

// Requirement: CL-F-08
func TestUserFacingMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "AppError returns its sanitized Public message, not the internal detail",
			err:  apperrors.NewUnauthorized(errors.New("entryhub: status 401: bad credentials, user_id=42")),
			want: apperrors.NewUnauthorized(nil).Public,
		},
		{
			name: "an AppError wrapped by another error is still unwrapped via errors.As",
			err:  wrapErr(apperrors.NewBadRequest(errors.New("entryhub: status 400: malformed email"))),
			want: apperrors.NewBadRequest(nil).Public,
		},
		{
			name: "a plain local error is shown via its own Error() text",
			err:  errors.New("--email is required"),
			want: "--email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := userFacingMessage(tt.err)
			if got != tt.want {
				t.Errorf("userFacingMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

// wrapErr wraps err in another error implementing Unwrap, the same way
// runRegister/runLogin wrap a downstream error with additional context
// (fmt.Errorf("...: %w", err)) before it reaches userFacingMessage.
func wrapErr(err error) error {
	return &wrappedError{err}
}

type wrappedError struct{ inner error }

func (w *wrappedError) Error() string { return "wrapped: " + w.inner.Error() }
func (w *wrappedError) Unwrap() error { return w.inner }

// Requirement: CL-F-09
func TestResolveCredentials(t *testing.T) {
	// notATerminal is the default prompt stub: it reproduces a
	// non-interactive stdin (script, CI, pipe), where the real
	// promptPassword reads nothing and reports ok=false.
	notATerminal := func() (string, bool, error) { return "", false, nil }

	tests := []struct {
		name        string
		args        []string
		envPassword string
		prompt      func() (string, bool, error)
		wantEmail   string
		wantPass    string
		wantErr     bool
	}{
		{
			name:      "email and password both supplied via flags",
			args:      []string{"--email=user@example.com", "--password=" + validPassword},
			wantEmail: "user@example.com",
			wantPass:  validPassword,
		},
		{
			name:        "password falls back to RAM_USB_PASSWORD when --password is absent",
			args:        []string{"--email=user@example.com"},
			envPassword: validPassword,
			wantEmail:   "user@example.com",
			wantPass:    validPassword,
		},
		{
			name:        "--password flag takes precedence over RAM_USB_PASSWORD",
			args:        []string{"--email=user@example.com", "--password=from-flag"},
			envPassword: "from-env",
			wantEmail:   "user@example.com",
			wantPass:    "from-flag",
		},
		{
			name:    "missing --email is rejected",
			args:    []string{"--password=" + validPassword},
			wantErr: true,
		},
		{
			name:    "missing password on a non-interactive stdin is rejected, never blocks on a prompt",
			args:    []string{"--email=user@example.com"},
			wantErr: true,
		},
		{
			name:      "missing password on an interactive terminal is prompted for",
			args:      []string{"--email=user@example.com"},
			prompt:    func() (string, bool, error) { return validPassword, true, nil },
			wantEmail: "user@example.com",
			wantPass:  validPassword,
		},
		{
			name:        "an explicitly supplied password is never overridden by the prompt",
			args:        []string{"--email=user@example.com"},
			envPassword: validPassword,
			prompt: func() (string, bool, error) {
				return "prompted-instead", true, errors.New("prompt must not be reached")
			},
			wantEmail: "user@example.com",
			wantPass:  validPassword,
		},
		{
			name:    "a failing terminal read is surfaced as an error",
			args:    []string{"--email=user@example.com"},
			prompt:  func() (string, bool, error) { return "", false, errors.New("read failed") },
			wantErr: true,
		},
		{
			name:    "unparseable flag is rejected",
			args:    []string{"--not-a-real-flag"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envPassword != "" {
				t.Setenv(envLoginPassword, tt.envPassword)
			} else {
				t.Setenv(envLoginPassword, "")
			}

			original := promptPassword
			t.Cleanup(func() { promptPassword = original })
			if tt.prompt != nil {
				promptPassword = tt.prompt
			} else {
				promptPassword = notATerminal
			}

			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			email, password, err := resolveCredentials(fs, tt.args)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveCredentials() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveCredentials() error = %v, want nil", err)
			}
			if email != tt.wantEmail {
				t.Errorf("email = %q, want %q", email, tt.wantEmail)
			}
			if password != tt.wantPass {
				t.Errorf("password = %q, want %q", password, tt.wantPass)
			}
		})
	}
}

// Requirement: CL-F-03
func TestRunLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/login" {
			t.Errorf("request path = %q, want /api/login", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	err := runLogin([]string{"--email=user@example.com", "--password=" + validPassword})
	if err != nil {
		t.Fatalf("runLogin() error = %v, want nil", err)
	}
}

// Requirement: CL-F-08
func TestRunLogin_MapsEntryHubErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication failed, user_id=7"})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	err := runLogin([]string{"--email=user@example.com", "--password=" + validPassword})

	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("runLogin() error = %v, want *apperrors.AppError", err)
	}
	if appErr.Status != http.StatusUnauthorized {
		t.Errorf("appErr.Status = %d, want %d", appErr.Status, http.StatusUnauthorized)
	}
}

// Requirement: CL-F-09
func TestRunLogin_LocalValidationFailure_DoesNotContactServer(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	err := runLogin([]string{"--email=not-an-email", "--password=" + validPassword})
	if err == nil {
		t.Fatal("runLogin() error = nil, want a local validation error")
	}
	if called {
		t.Error("runLogin() contacted Entry-Hub despite failing local validation (CL-F-09)")
	}
}

// Requirement: CL-F-03
func TestRunLogin_MissingEntryHubURL(t *testing.T) {
	t.Setenv(envEntryHubURL, "")
	err := runLogin([]string{"--email=user@example.com", "--password=" + validPassword})
	if err == nil {
		t.Fatal("runLogin() error = nil, want an error when RAM_USB_ENTRY_HUB_URL is unset")
	}
}

// Requirement: CL-F-03
func TestRunLogin_MissingCredentials(t *testing.T) {
	t.Setenv(envEntryHubURL, "https://example.invalid")
	err := runLogin([]string{"--password=" + validPassword})
	if err == nil {
		t.Fatal("runLogin() error = nil, want an error for a missing --email")
	}
}

// Requirement: CL-F-01
func TestRunRegister_MissingEntryHubURL(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envEntryHubURL, "")
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword}, &execrunner.Fake{})
	if err == nil {
		t.Fatal("runRegister() error = nil, want an error when RAM_USB_ENTRY_HUB_URL is unset")
	}
}

// Requirement: CL-F-09
func TestRunRegister_LocalValidationFailure_DoesNotContactServer(t *testing.T) {
	isolateConfigDir(t)
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	err := runRegister([]string{"--email=not-an-email", "--password=" + validPassword}, &execrunner.Fake{})
	if err == nil {
		t.Fatal("runRegister() error = nil, want a local validation error")
	}
	if called {
		t.Error("runRegister() contacted Entry-Hub despite failing local validation (CL-F-09)")
	}
}

// Requirement: CL-F-08
func TestRunRegister_MapsEntryHubErrorStatus(t *testing.T) {
	isolateConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal detail that must never reach the user"})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword}, &execrunner.Fake{})
	if err == nil {
		t.Fatal("runRegister() error = nil, want an error")
	}

	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("runRegister() error = %v, want *apperrors.AppError", err)
	}
	if got := userFacingMessage(err); got == "internal detail that must never reach the user" {
		t.Errorf("userFacingMessage() leaked the server's internal detail: %q", got)
	}
}

// Requirement: CL-F-02
func TestRunRegister_Success_PersistsPosixUsername(t *testing.T) {
	isolateConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users" {
			t.Errorf("request path = %q, want /api/users", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["ssh_public_key"] == "" {
			t.Error("request body carried no ssh_public_key (CL-F-01/CL-F-02)")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"posix_username": "user000001"})
	}))
	defer server.Close()

	// No RAM_USB_HEADSCALE_URL set, and the server above returns no
	// pre_auth_key: this keeps the test inside the branch that returns
	// before ever reaching mesh.Join.
	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "")

	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword}, &execrunner.Fake{})
	if err != nil {
		t.Fatalf("runRegister() error = %v, want nil", err)
	}

	dir, err := sshkey.ConfigDir()
	if err != nil {
		t.Fatalf("sshkey.ConfigDir() error = %v", err)
	}
	got, ok, err := clientstate.LoadPosixUsername(dir)
	if err != nil {
		t.Fatalf("clientstate.LoadPosixUsername() error = %v", err)
	}
	if !ok {
		t.Fatal("clientstate.LoadPosixUsername() found no saved username after a successful register")
	}
	if got != "user000001" {
		t.Errorf("saved posix username = %q, want user000001", got)
	}

	if _, ok, err := sshkey.Load(dir); err != nil || !ok {
		t.Errorf("sshkey.Load() after register = ok=%v, err=%v, want ok=true, err=nil (CL-F-01)", ok, err)
	}
}

// Requirement: CL-F-04
func TestRunRegister_PreauthKeyWithoutHeadscaleURL_SkipsMeshJoin(t *testing.T) {
	isolateConfigDir(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"posix_username": "user000002",
			"pre_auth_key":   "preauth-abc",
		})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "")

	// With RAM_USB_HEADSCALE_URL unset, runRegister must return before
	// calling mesh.Join.
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword}, &execrunner.Fake{})
	if err != nil {
		t.Fatalf("runRegister() error = %v, want nil", err)
	}
}

// Requirement: CL-F-04
func TestRunRegister_JoinsMeshOnSuccess(t *testing.T) {
	setupConfigDir(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"posix_username": "user000001",
			"pre_auth_key":   "preauth-abc",
		})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "https://headscale.example.com")

	fake := &execrunner.Fake{Output: []byte("Success.")}

	err := runRegister([]string{"--email=user@example.com", "--password=Str0ng!Pass"}, fake)
	if err != nil {
		t.Fatalf("runRegister() error = %v, want nil", err)
	}

	want := [][]string{{"tailscale", "up", "--login-server=https://headscale.example.com", "--authkey=preauth-abc"}}
	if !reflect.DeepEqual(fake.Calls, want) {
		t.Errorf("fake.Calls = %v, want %v", fake.Calls, want)
	}
}

// Requirement: CL-F-04
func TestRunRegister_MeshJoinFailure_IsPropagated(t *testing.T) {
	setupConfigDir(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"posix_username": "user000002",
			"pre_auth_key":   "preauth-def",
		})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "https://headscale.example.com")

	fake := &execrunner.Fake{
		Output: []byte("tailscale: needs sudo"),
		Err:    errors.New("exit status 1"),
	}

	err := runRegister([]string{"--email=user@example.com", "--password=Str0ng!Pass"}, fake)
	if !errors.Is(err, mesh.ErrJoinFailed) {
		t.Fatalf("runRegister() error = %v, want to wrap mesh.ErrJoinFailed", err)
	}
	if len(fake.Calls) != 1 {
		t.Errorf("fake.Calls = %v, want exactly one tailscale invocation", fake.Calls)
	}
}

// Requirement: CL-F-04
func TestRunRegister_NoHeadscaleURL_SkipsMeshJoin(t *testing.T) {
	setupConfigDir(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"posix_username": "user000003",
			"pre_auth_key":   "preauth-ghi",
		})
	}))
	defer server.Close()

	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "")

	fake := &execrunner.Fake{}

	err := runRegister([]string{"--email=user@example.com", "--password=Str0ng!Pass"}, fake)
	if err != nil {
		t.Fatalf("runRegister() error = %v, want nil", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("fake.Calls = %v, want no tailscale invocation without a login server", fake.Calls)
	}
}

// Requirement: CL-F-06
func TestRunBackup_ArgumentValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no path argument", args: []string{}},
		{name: "too many arguments", args: []string{"/tmp/a", "/tmp/b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runBackup(tt.args, &execrunner.Fake{})
			if err == nil {
				t.Fatal("runBackup() error = nil, want an error")
			}
		})
	}
}

// Requirement: CL-F-06
func TestRunBackup_Success(t *testing.T) {
	_, posixUsername := setupRegisteredClient(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	fake := &execrunner.Fake{Output: []byte("snapshot abc123 saved")}
	localPath := filepath.Join(t.TempDir(), "documents")

	err := runBackup([]string{localPath}, fake)
	if err != nil {
		t.Fatalf("runBackup() error = %v, want nil", err)
	}

	if len(fake.Calls) != 2 {
		t.Fatalf("fake.Calls = %v, want exactly 2 invocations (init, backup)", fake.Calls)
	}
	initCall, backupCall := fake.Calls[0], fake.Calls[1]

	if initCall[0] != "restic" || initCall[len(initCall)-1] != "init" {
		t.Errorf("first call = %v, want a \"restic ... init\" invocation", initCall)
	}
	if backupCall[0] != "restic" {
		t.Errorf("second call = %v, want to invoke restic", backupCall)
	}
	if got := backupCall[len(backupCall)-2:]; !reflect.DeepEqual(got, []string{"backup", localPath}) {
		t.Errorf("second call's trailing args = %v, want [backup %s]", got, localPath)
	}
	if !containsSubstring(backupCall, posixUsername) {
		t.Errorf("backup call = %v, want it to address repository user %q", backupCall, posixUsername)
	}
}

// Requirement: CL-F-06
func TestRunBackup_InitFailure_IsPropagated(t *testing.T) {
	setupRegisteredClient(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	fake := &execrunner.Fake{
		Output: []byte("permission denied"),
		Err:    errors.New("exit status 1"),
	}

	err := runBackup([]string{filepath.Join(t.TempDir(), "documents")}, fake)
	if !errors.Is(err, restic.ErrRepositoryOperationFailed) {
		t.Fatalf("runBackup() error = %v, want to wrap restic.ErrRepositoryOperationFailed", err)
	}
	if len(fake.Calls) != 1 {
		t.Errorf("fake.Calls = %v, want backup never attempted after init failed", fake.Calls)
	}
}

// Requirement: CL-F-06
func TestRunBackup_BackupFailure_IsPropagated(t *testing.T) {
	setupRegisteredClient(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	// "already initialized" is restic.Init's own success marker (Init is
	// safe to call on every backup, not just the first) - combining it
	// with a non-nil Err makes Init succeed while every OTHER restic
	// invocation (Backup here) still observes the failure, without
	// needing to reconstruct restic's internal -r/-o flag values to key
	// execrunner.Fake.ErrFor precisely.
	fake := &execrunner.Fake{
		Output: []byte("already initialized"),
		Err:    errors.New("exit status 1"),
	}

	err := runBackup([]string{filepath.Join(t.TempDir(), "documents")}, fake)
	if !errors.Is(err, restic.ErrRepositoryOperationFailed) {
		t.Fatalf("runBackup() error = %v, want to wrap restic.ErrRepositoryOperationFailed", err)
	}
	if len(fake.Calls) != 2 {
		t.Errorf("fake.Calls = %v, want both init (succeeding) and backup (failing) attempted", fake.Calls)
	}
}

// Requirement: CL-F-07
func TestRunRestore_ArgumentValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no snapshot argument", args: []string{"--target=/tmp/out"}},
		{name: "missing --target", args: []string{"snapshot-id"}},
		{name: "too many positional arguments", args: []string{"snap1", "snap2", "--target=/tmp/out"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runRestore(tt.args, &execrunner.Fake{})
			if err == nil {
				t.Fatal("runRestore() error = nil, want an error")
			}
		})
	}
}

// Requirement: CL-F-07
func TestRunRestore_Success(t *testing.T) {
	_, posixUsername := setupRegisteredClient(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	fake := &execrunner.Fake{Output: []byte("restored 12 files")}
	target := t.TempDir()

	err := runRestore([]string{"--target=" + target, "latest"}, fake)
	if err != nil {
		t.Fatalf("runRestore() error = %v, want nil", err)
	}

	if len(fake.Calls) != 1 {
		t.Fatalf("fake.Calls = %v, want exactly 1 invocation", fake.Calls)
	}
	call := fake.Calls[0]
	if call[0] != "restic" {
		t.Errorf("call = %v, want to invoke restic", call)
	}
	if got := call[len(call)-4:]; !reflect.DeepEqual(got, []string{"restore", "latest", "--target", target}) {
		t.Errorf("call's trailing args = %v, want [restore latest --target %s]", got, target)
	}
	if !containsSubstring(call, posixUsername) {
		t.Errorf("restore call = %v, want it to address repository user %q", call, posixUsername)
	}
}

// Requirement: CL-F-07
func TestRunRestore_Failure_IsPropagated(t *testing.T) {
	setupRegisteredClient(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	fake := &execrunner.Fake{
		Output: []byte("no such snapshot"),
		Err:    errors.New("exit status 1"),
	}
	target := t.TempDir()

	err := runRestore([]string{"--target=" + target, "does-not-exist"}, fake)
	if !errors.Is(err, restic.ErrRepositoryOperationFailed) {
		t.Fatalf("runRestore() error = %v, want to wrap restic.ErrRepositoryOperationFailed", err)
	}
	if len(fake.Calls) != 1 {
		t.Errorf("fake.Calls = %v, want exactly 1 invocation", fake.Calls)
	}
}

// Requirement: CL-F-06
func TestResticConfig_MissingKeyPair(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	_, err := resticConfig(&execrunner.Fake{})
	if err == nil {
		t.Fatal("resticConfig() error = nil, want an error when no ssh key pair was generated yet")
	}
}

// Requirement: CL-F-06
func TestResticConfig_MissingPosixUsername(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	dir, err := sshkey.ConfigDir()
	if err != nil {
		t.Fatalf("sshkey.ConfigDir() error = %v", err)
	}
	if _, err := sshkey.EnsureKeyPair(dir); err != nil {
		t.Fatalf("sshkey.EnsureKeyPair() error = %v", err)
	}

	_, err = resticConfig(&execrunner.Fake{})
	if err == nil {
		t.Fatal("resticConfig() error = nil, want an error when no posix username was saved yet")
	}
}

// Requirement: CL-F-06
func TestResticConfig_MissingStorageHost(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envStorageHost, "")

	dir, err := sshkey.ConfigDir()
	if err != nil {
		t.Fatalf("sshkey.ConfigDir() error = %v", err)
	}
	if _, err := sshkey.EnsureKeyPair(dir); err != nil {
		t.Fatalf("sshkey.EnsureKeyPair() error = %v", err)
	}
	if err := clientstate.SavePosixUsername(dir, "user000003"); err != nil {
		t.Fatalf("clientstate.SavePosixUsername() error = %v", err)
	}

	_, err = resticConfig(&execrunner.Fake{})
	if err == nil {
		t.Fatal("resticConfig() error = nil, want an error when RAM_USB_STORAGE_HOST is unset")
	}
}

// Requirement: CL-F-06
func TestResticConfig_Success(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	dir, err := sshkey.ConfigDir()
	if err != nil {
		t.Fatalf("sshkey.ConfigDir() error = %v", err)
	}
	keyPair, err := sshkey.EnsureKeyPair(dir)
	if err != nil {
		t.Fatalf("sshkey.EnsureKeyPair() error = %v", err)
	}
	if err := clientstate.SavePosixUsername(dir, "user000004"); err != nil {
		t.Fatalf("clientstate.SavePosixUsername() error = %v", err)
	}

	cfg, err := resticConfig(&execrunner.Fake{})
	if err != nil {
		t.Fatalf("resticConfig() error = %v, want nil", err)
	}
	if cfg.Host != "storage-service.mesh" {
		t.Errorf("cfg.Host = %q, want storage-service.mesh", cfg.Host)
	}
	if cfg.PosixUsername != "user000004" {
		t.Errorf("cfg.PosixUsername = %q, want user000004", cfg.PosixUsername)
	}
	if cfg.PrivateKeyPath != keyPair.PrivateKeyPath {
		t.Errorf("cfg.PrivateKeyPath = %q, want %q", cfg.PrivateKeyPath, keyPair.PrivateKeyPath)
	}
	if cfg.RepositoryPassword == "" {
		t.Error("cfg.RepositoryPassword is empty, want a generated repository password")
	}
	if cfg.Runner == nil {
		t.Error("cfg.Runner is nil, want the explicitly injected execrunner.Fake")
	}
}

// containsSubstring reports whether any element of args contains want as a
// substring - restic's own "-o sftp.command=ssh -i ... -l <user> ..."
// value is a single space-containing CLI argument, not split across
// separate elements, so an exact-equality check would never match.
func containsSubstring(args []string, want string) bool {
	for _, a := range args {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}
