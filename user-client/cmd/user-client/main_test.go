package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/user-client/internal/clientstate"
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
	tests := []struct {
		name        string
		args        []string
		envPassword string
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
			name:    "missing password (no flag, no env var) is rejected",
			args:    []string{"--email=user@example.com"},
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
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword})
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
	err := runRegister([]string{"--email=not-an-email", "--password=" + validPassword})
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
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword})
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
		if r.URL.Path != "/api/register" {
			t.Errorf("request path = %q, want /api/register", r.URL.Path)
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
	// before ever reaching mesh.Join, whose only caller in main.go passes
	// a hardcoded execrunner.Real{} that would spawn a real `tailscale`
	// process (see this file's final report for why that path is not
	// covered here without a main.go refactor).
	t.Setenv(envEntryHubURL, server.URL)
	t.Setenv(envHeadscaleURL, "")

	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword})
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
	// calling mesh.Join (which would otherwise try to exec a real
	// `tailscale` binary via the hardcoded execrunner.Real{}).
	err := runRegister([]string{"--email=user@example.com", "--password=" + validPassword})
	if err != nil {
		t.Fatalf("runRegister() error = %v, want nil", err)
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
			err := runBackup(tt.args)
			if err == nil {
				t.Fatal("runBackup() error = nil, want an error")
			}
		})
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
			err := runRestore(tt.args)
			if err == nil {
				t.Fatal("runRestore() error = nil, want an error")
			}
		})
	}
}

// Requirement: CL-F-06
func TestResticConfig_MissingKeyPair(t *testing.T) {
	isolateConfigDir(t)
	t.Setenv(envStorageHost, "storage-service.mesh")

	_, err := resticConfig()
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

	_, err = resticConfig()
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

	_, err = resticConfig()
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

	cfg, err := resticConfig()
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
		t.Error("cfg.Runner is nil, want the real execrunner")
	}
}
