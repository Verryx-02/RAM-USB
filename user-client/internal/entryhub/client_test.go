package entryhub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

const validPassword = "Str0ng!Pass"
const validSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXhx0hFrRWeUcQVbYyIVwUp3ChRIkbcVUWIfyzcPKgL comment\n"

// Requirement: CL-F-09
func TestRegister_LocalValidationFailure_DoesNotSendRequest(t *testing.T) {
	tests := []struct {
		name string
		req  validation.RegisterRequest
	}{
		{
			name: "invalid email",
			req:  validation.RegisterRequest{Email: "not-an-email", Password: validPassword, SSHPublicKey: validSSHKey},
		},
		{
			name: "password too short",
			req:  validation.RegisterRequest{Email: "user@example.com", Password: "short", SSHPublicKey: validSSHKey},
		},
		{
			name: "invalid ssh key",
			req:  validation.RegisterRequest{Email: "user@example.com", Password: validPassword, SSHPublicKey: "not-a-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				called = true
			}))
			defer server.Close()

			c := New(server.URL)
			_, err := c.Register(context.Background(), tt.req)

			if !errors.Is(err, ErrLocalValidationFailed) {
				t.Errorf("Register() error = %v, want ErrLocalValidationFailed", err)
			}
			if called {
				t.Errorf("Register() sent an HTTP request despite local validation failure (CL-F-09)")
			}
		})
	}
}

// Requirement: CL-F-02
func TestRegister_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != RegisterPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, RegisterPath)
		}
		var got validation.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registerResponse{PosixUsername: "user000001", PreauthKey: "preauth-abc"})
	}))
	defer server.Close()

	c := New(server.URL)
	req := validation.RegisterRequest{Email: "user@example.com", Password: validPassword, SSHPublicKey: validSSHKey}
	result, err := c.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Register() error = %v, want nil", err)
	}
	if result.PosixUsername != "user000001" {
		t.Errorf("result.PosixUsername = %q, want user000001", result.PosixUsername)
	}
	if result.PreauthKey != "preauth-abc" {
		t.Errorf("result.PreauthKey = %q, want preauth-abc", result.PreauthKey)
	}
}

// Requirement: CL-F-08
func TestRegister_MapsErrorStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantPublic string
	}{
		{name: "bad request", status: http.StatusBadRequest, wantPublic: "the request could not be processed"},
		{name: "conflict maps to internal (unmapped by CL-F-08's set)", status: http.StatusConflict, wantPublic: "the request could not be completed"},
		{name: "internal server error", status: http.StatusInternalServerError, wantPublic: "the request could not be completed"},
		{name: "bad gateway", status: http.StatusBadGateway, wantPublic: "the request could not be completed"},
		{name: "service unavailable", status: http.StatusServiceUnavailable, wantPublic: "the request could not be completed"},
		{name: "gateway timeout", status: http.StatusGatewayTimeout, wantPublic: "the request could not be completed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(appErrorResponse{Error: "internal detail that must never reach the user"})
			}))
			defer server.Close()

			c := New(server.URL)
			req := validation.RegisterRequest{Email: "user@example.com", Password: validPassword, SSHPublicKey: validSSHKey}
			_, err := c.Register(context.Background(), req)

			var appErr *apperrors.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("Register() error = %v, want *apperrors.AppError", err)
			}
			if appErr.Public != tt.wantPublic {
				t.Errorf("appErr.Public = %q, want %q", appErr.Public, tt.wantPublic)
			}
			if appErr.Public == "internal detail that must never reach the user" {
				t.Errorf("appErr.Public leaked the server's internal detail")
			}
		})
	}
}

// Requirement: CL-F-08
func TestRegister_Unreachable(t *testing.T) {
	c := New("https://127.0.0.1:1") // nothing listens here
	req := validation.RegisterRequest{Email: "user@example.com", Password: validPassword, SSHPublicKey: validSSHKey}
	_, err := c.Register(context.Background(), req)

	if !errors.Is(err, ErrUnreachable) {
		t.Errorf("Register() error = %v, want ErrUnreachable", err)
	}
}

// Requirement: CL-F-09
func TestLogin_LocalValidationFailure_DoesNotSendRequest(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer server.Close()

	c := New(server.URL)
	err := c.Login(context.Background(), validation.LoginRequest{Email: "not-an-email", Password: validPassword})

	if !errors.Is(err, ErrLocalValidationFailed) {
		t.Errorf("Login() error = %v, want ErrLocalValidationFailed", err)
	}
	if called {
		t.Errorf("Login() sent an HTTP request despite local validation failure (CL-F-09)")
	}
}

// Requirement: CL-F-03
func TestLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != LoginPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, LoginPath)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	c := New(server.URL)
	err := c.Login(context.Background(), validation.LoginRequest{Email: "user@example.com", Password: validPassword})
	if err != nil {
		t.Fatalf("Login() error = %v, want nil", err)
	}
}

// Requirement: CL-F-08
func TestLogin_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(appErrorResponse{Error: "authentication failed"})
	}))
	defer server.Close()

	c := New(server.URL)
	err := c.Login(context.Background(), validation.LoginRequest{Email: "user@example.com", Password: validPassword})

	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("Login() error = %v, want *apperrors.AppError", err)
	}
	if appErr.Status != http.StatusUnauthorized {
		t.Errorf("appErr.Status = %d, want %d", appErr.Status, http.StatusUnauthorized)
	}
}
