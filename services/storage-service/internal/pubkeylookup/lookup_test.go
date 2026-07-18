package pubkeylookup

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/internal/v1/public-key/user7k2m9x" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ssh_public_key": "ssh-ed25519 AAAAC3 comment"}`))
	}))
	defer server.Close()

	key, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, "user7k2m9x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "ssh-ed25519 AAAAC3 comment" {
		t.Fatalf("unexpected key: %q", key)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_MalformedJSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()

	_, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, "user7k2m9x")
	if !errors.Is(err, ErrLookupFailed) {
		t.Fatalf("expected ErrLookupFailed, got %v", err)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, "user7k2m9x")
	if !errors.Is(err, ErrPublicKeyNotFound) {
		t.Fatalf("expected ErrPublicKeyNotFound, got %v", err)
	}
	if errors.Is(err, ErrLookupFailed) {
		t.Fatalf("ErrPublicKeyNotFound must not also match ErrLookupFailed: %v", err)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	_, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, "user7k2m9x")
	if !errors.Is(err, ErrLookupFailed) {
		t.Fatalf("expected ErrLookupFailed, got %v", err)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_UnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, "user7k2m9x")
	if !errors.Is(err, ErrLookupFailed) {
		t.Fatalf("expected ErrLookupFailed, got %v", err)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_ContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := FetchAuthorizedKeysLine(ctx, server.Client(), server.URL, "user7k2m9x")
	if !errors.Is(err, ErrLookupFailed) {
		t.Fatalf("expected ErrLookupFailed, got %v", err)
	}
}

// Requirement: ST-F-11
func TestFetchAuthorizedKeysLine_MalformedUsernameRejectedBeforeCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should never be contacted for a malformed username")
	}))
	defer server.Close()

	tests := []struct {
		name          string
		posixUsername string
	}{
		{"empty", ""},
		{"too short", "user123"},
		{"too long", "user1234567"},
		{"uppercase", "userABCDEF"},
		{"missing prefix", "xser123456"},
		{"symbol", "user12-456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FetchAuthorizedKeysLine(context.Background(), server.Client(), server.URL, tt.posixUsername)
			if !errors.Is(err, ErrInvalidPosixUsername) {
				t.Fatalf("expected ErrInvalidPosixUsername, got %v", err)
			}
		})
	}
}
