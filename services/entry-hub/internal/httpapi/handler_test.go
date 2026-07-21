package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
)

// Fixed, non-secret test fixtures (not real credentials/keys).
const (
	testEmail        = "user@example.com"
	testPassword     = "Str0ng!Pass"
	testSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"
)

// fakeSecuritySwitch is a hand-written fake implementing
// httpapi.SecuritySwitchClient (CONTRIBUTING.md §7.5).
type fakeSecuritySwitch struct {
	registerResult securityswitch.Result
	loginResult    securityswitch.Result
	registerCalled bool
	loginCalled    bool
}

func (f *fakeSecuritySwitch) Register(_ context.Context, _ validation.RegisterRequest) securityswitch.Result {
	f.registerCalled = true
	return f.registerResult
}

func (f *fakeSecuritySwitch) Login(_ context.Context, _ validation.LoginRequest) securityswitch.Result {
	f.loginCalled = true
	return f.loginResult
}

// newTestHandler builds a Handler wired to a hand-written fake and a
// buffer-backed logger, mirroring
// services/security-switch/internal/httpapi/handler_test.go's
// newTestHandler exactly (EH-F-06's "no user-identifying value in the
// log" needs the buffer, not just status-code assertions).
func newTestHandler(securitySwitch httpapi.SecuritySwitchClient) (*httpapi.Handler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &httpapi.Handler{
		SecuritySwitch: securitySwitch,
		Metrics:        &httpapi.Counters{},
		Logger:         logger,
	}
	return h, &logBuf
}

func registerRequestBody(email, password, sshKey string) string {
	body, _ := json.Marshal(map[string]string{
		"email":          email,
		"password":       password,
		"ssh_public_key": sshKey,
	})
	return string(body)
}

func loginRequestBody(email, password string) string {
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	return string(body)
}

// Requirement: EH-F-01
func TestHandler_Health(t *testing.T) {
	h := &httpapi.Handler{}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.HealthPath, nil)
	rec := httptest.NewRecorder()

	h.Health(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf(`body["status"] = %q, want "ok"`, body["status"])
	}
}

// Requirement: EH-F-07
// Requirement: EH-F-08
func TestHandler_Register_SuccessRelaysResponseUnchanged(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		registerResult: securityswitch.Result{
			StatusCode:  http.StatusCreated,
			ContentType: "application/json",
			Body:        []byte(`{"posix_username":"user7k2m9x"}`),
		},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if !securitySwitch.registerCalled {
		t.Fatal("expected SecuritySwitch.Register to be called on successful validation")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if rec.Body.String() != `{"posix_username":"user7k2m9x"}` {
		t.Fatalf("body = %q, want Security-Switch's response relayed unchanged", rec.Body.String())
	}
	if got := h.Metrics.Snapshot(); got.RequestCount != 1 || got.ErrorCount != 0 {
		t.Fatalf("counters after success = %+v, want RequestCount=1, ErrorCount=0", got)
	}
}

// Requirement: EH-F-08
func TestHandler_Register_DuplicateRelayedUnchanged(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		registerResult: securityswitch.Result{
			StatusCode:  http.StatusConflict,
			ContentType: "application/json",
			Body:        []byte(`{"error":"the request could not be completed"}`),
		},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d (Security-Switch's own 409 must be relayed, not reconstructed)", rec.Code, http.StatusConflict)
	}
}

// Requirement: EH-F-08
func TestHandler_Register_MissingContentTypeDefaultsToJSON(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		registerResult: securityswitch.Result{
			StatusCode: http.StatusCreated,
			// ContentType deliberately left empty: every response
			// Security-Switch's own httpapi package writes carries
			// application/json, but writeForwardedResponse must still
			// fall back safely if it ever doesn't.
			Body: []byte(`{"posix_username":"user7k2m9x"}`),
		},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q (fallback when Security-Switch omits it)", got, "application/json")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

// Requirement: EH-F-09
func TestHandler_Register_SecuritySwitchUnreachableMapsToBadGateway(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		registerResult: securityswitch.Result{Err: securityswitch.ErrSecuritySwitchUnreachable},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// Requirement: EH-F-09
func TestHandler_Register_SecuritySwitchTimeoutMapsToServiceUnavailable(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		registerResult: securityswitch.Result{Err: securityswitch.ErrSecuritySwitchTimeout},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(registerRequestBody(testEmail, testPassword, testSSHPublicKey)))
	rec := httptest.NewRecorder()

	h.Register(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (EH-F-09 uses 503 for a timed-out downstream call, not 504)", rec.Code, http.StatusServiceUnavailable)
	}
}

// Requirement: EH-F-02
// Requirement: EH-F-04
// Requirement: EH-F-06
func TestHandler_Register_ValidationFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty email", registerRequestBody("", testPassword, testSSHPublicKey)},
		{"malformed email", registerRequestBody("not-an-email", testPassword, testSSHPublicKey)},
		{"weak password", registerRequestBody(testEmail, "weak", testSSHPublicKey)},
		{"malformed ssh key", registerRequestBody(testEmail, testPassword, "not-an-ssh-key")},
		{"malformed json", `{"email":`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			securitySwitch := &fakeSecuritySwitch{}
			h, logBuf := newTestHandler(securitySwitch)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.RegisterPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if securitySwitch.registerCalled {
				t.Fatal("EH-F-06: a validation failure must not forward the request to Security-Switch")
			}

			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] == "" {
				t.Fatal("expected a non-empty generic error message")
			}
			lowerMsg := strings.ToLower(resp["error"])
			for _, f := range []string{"email", "password", "ssh"} {
				if strings.Contains(lowerMsg, f) {
					t.Fatalf("response body must not specify which problem was encountered, got: %q", resp["error"])
				}
			}

			logged := logBuf.String()
			for _, secret := range []string{testEmail, testPassword, testSSHPublicKey, "not-an-email", "weak", "not-an-ssh-key"} {
				if secret == "" {
					continue
				}
				if strings.Contains(logged, secret) {
					t.Fatalf("log must not identify the user, but contains %q:\n%s", secret, logged)
				}
			}
		})
	}
}

// Requirement: EH-F-07
// Requirement: EH-F-08
func TestHandler_Login_SuccessRelaysResponseUnchanged(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		loginResult: securityswitch.Result{
			StatusCode:  http.StatusOK,
			ContentType: "application/json",
			Body:        []byte(`{"status":"ok"}`),
		},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if !securitySwitch.loginCalled {
		t.Fatal("expected SecuritySwitch.Login to be called on successful validation")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Fatalf("body = %q, want Security-Switch's response relayed unchanged", rec.Body.String())
	}
}

// Requirement: EH-F-08
func TestHandler_Login_UnauthorizedRelayedUnchanged(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		loginResult: securityswitch.Result{
			StatusCode:  http.StatusUnauthorized,
			ContentType: "application/json",
			Body:        []byte(`{"error":"authentication failed"}`),
		},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (Security-Switch's own 401 must be relayed, identical for both nonexistent-email and wrong-password cases, per DV-F-15/UC-02)", rec.Code, http.StatusUnauthorized)
	}
}

// Requirement: EH-F-09
func TestHandler_Login_SecuritySwitchUnreachableMapsToBadGateway(t *testing.T) {
	securitySwitch := &fakeSecuritySwitch{
		loginResult: securityswitch.Result{Err: securityswitch.ErrSecuritySwitchUnreachable},
	}
	h, _ := newTestHandler(securitySwitch)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.LoginPath, strings.NewReader(loginRequestBody(testEmail, testPassword)))
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

// Requirement: EH-F-03
// Requirement: EH-F-05
// Requirement: EH-F-06
func TestHandler_Login_ValidationFailure(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty email", loginRequestBody("", testPassword)},
		{"malformed email", loginRequestBody("not-an-email", testPassword)},
		{"empty password", loginRequestBody(testEmail, "")},
		{"malformed json", `{"email":`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			securitySwitch := &fakeSecuritySwitch{}
			h, logBuf := newTestHandler(securitySwitch)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.LoginPath, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			h.Login(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if securitySwitch.loginCalled {
				t.Fatal("EH-F-06: a validation failure must not forward the request to Security-Switch")
			}

			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			lowerMsg := strings.ToLower(resp["error"])
			for _, f := range []string{"email", "password"} {
				if strings.Contains(lowerMsg, f) {
					t.Fatalf("response body must not specify which problem was encountered, got: %q", resp["error"])
				}
			}

			logged := logBuf.String()
			for _, secret := range []string{testEmail, testPassword, "not-an-email"} {
				if secret == "" {
					continue
				}
				if strings.Contains(logged, secret) {
					t.Fatalf("log must not identify the user, but contains %q:\n%s", secret, logged)
				}
			}
		})
	}
}
