package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// fakePublicKeyStore is a hand-written fake implementing PublicKeyStore
// (CONTRIBUTING.md §7.5).
type fakePublicKeyStore struct {
	key string
	err error
}

func (f *fakePublicKeyStore) GetSSHPublicKey(_ context.Context, _ string) (string, error) {
	return f.key, f.err
}

// newTestPublicKeyHandler builds a PublicKeyHandler wired to a
// hand-written fake and a buffer-backed logger, mirroring
// newTestHandler's shape in handler_test.go.
func newTestPublicKeyHandler(store PublicKeyStore) (*PublicKeyHandler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &PublicKeyHandler{
		Store:   store,
		Metrics: &Counters{},
		Logger:  logger,
	}
	return h, &logBuf
}

// doPublicKeyRequest routes a GET request for posixUsername through a real
// http.ServeMux registered under PublicKeyPath, so the test exercises the
// same {posix_username} wildcard extraction production code relies on,
// not a hand-set r.SetPathValue bypassing it.
func doPublicKeyRequest(h *PublicKeyHandler, posixUsername string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc(PublicKeyPath, h.PublicKey)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/internal/v1/public-key/"+posixUsername, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

const testPosixUsername = "user1a2b3c"

// Requirement: ST-F-11
func TestPublicKeyHandler_Found(t *testing.T) {
	const wantKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"

	h, _ := newTestPublicKeyHandler(&fakePublicKeyStore{key: wantKey})
	rec := doPublicKeyRequest(h, testPosixUsername)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		SSHPublicKey string `json:"ssh_public_key"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body.SSHPublicKey != wantKey {
		t.Fatalf("ssh_public_key = %q, want %q", body.SSHPublicKey, wantKey)
	}
}

// Requirement: ST-F-11
func TestPublicKeyHandler_NotFound(t *testing.T) {
	h, logBuf := newTestPublicKeyHandler(&fakePublicKeyStore{err: storage.ErrPosixUsernameNotFound})
	rec := doPublicKeyRequest(h, testPosixUsername)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if strings.Contains(rec.Body.String(), "storage:") {
		t.Fatalf("response body leaked internal detail: %s", rec.Body.String())
	}
	_ = logBuf
}

// Requirement: ST-F-11
func TestPublicKeyHandler_LookupFailureMapsToInternal(t *testing.T) {
	h, logBuf := newTestPublicKeyHandler(&fakePublicKeyStore{err: errors.New("connection reset")})
	rec := doPublicKeyRequest(h, testPosixUsername)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Fatalf("response body leaked internal detail: %s", rec.Body.String())
	}
	if !strings.Contains(logBuf.String(), "connection reset") {
		t.Fatalf("log should contain the internal error detail, got: %s", logBuf.String())
	}
}

// Requirement: ST-F-11
func TestPublicKeyHandler_MalformedUsernameRejected(t *testing.T) {
	tests := []struct {
		name          string
		posixUsername string
	}{
		{"too short", "user1a2"},
		{"wrong prefix", "admin1a2b3c"},
		{"uppercase not allowed", "userABCDEF"},
		{"empty", ""},
	}

	// Store is never called in any of these cases — the fake would panic
	// if it were, since none of it configures a key or error.
	store := &fakePublicKeyStore{err: errors.New("store must not be called for a malformed username")}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, logBuf := newTestPublicKeyHandler(store)
			rec := doPublicKeyRequest(h, tt.posixUsername)

			if tt.posixUsername == "" {
				// An empty {posix_username} segment does not match
				// ServeMux's wildcard at all (a wildcard must match a
				// non-empty segment), so this request 404s at the mux
				// level before PublicKey ever runs — still a safe,
				// fail-closed outcome, just not through this handler's
				// own malformed-format branch.
				if rec.Code != http.StatusNotFound {
					t.Fatalf("status = %d, want %d (mux-level not-found for an empty path segment)", rec.Code, http.StatusNotFound)
				}
				return
			}

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if strings.Contains(logBuf.String(), tt.posixUsername) {
				t.Fatalf("log leaked the raw posix_username value: %s", logBuf.String())
			}
		})
	}
}

// Requirement: ST-F-11
func TestPublicKeyHandler_MetricsCounted(t *testing.T) {
	h, _ := newTestPublicKeyHandler(&fakePublicKeyStore{key: "ssh-ed25519 AAAA... user@client"})

	doPublicKeyRequest(h, testPosixUsername)

	snap := h.Metrics.Snapshot()
	if snap.RequestCount != 1 {
		t.Fatalf("RequestCount = %d, want 1", snap.RequestCount)
	}
	if snap.ErrorCount != 0 {
		t.Fatalf("ErrorCount = %d, want 0", snap.ErrorCount)
	}
}
