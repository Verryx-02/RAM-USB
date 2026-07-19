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
	"time"

	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

const testEmail = "user@example.com"

// fakeMesh is a hand-written fake implementing MeshProvisioner
// (CONTRIBUTING.md §7.5).
type fakeMesh struct {
	createKey   string
	createErr   error
	grantErr    error
	grantNodeID uint64
	createCalls []string
	grantCalls  []string
}

func (f *fakeMesh) CreateMeshUser(_ context.Context, email string) (string, error) {
	f.createCalls = append(f.createCalls, email)
	if f.createErr != nil {
		return "", f.createErr
	}
	return f.createKey, nil
}

func (f *fakeMesh) GrantStorageAccess(_ context.Context, email string) (uint64, error) {
	f.grantCalls = append(f.grantCalls, email)
	if f.grantErr != nil {
		return 0, f.grantErr
	}
	return f.grantNodeID, nil
}

// fakeGrantRecorder is a hand-written fake implementing GrantRecorder
// (CONTRIBUTING.md §7.5), letting tests assert NM-F-11's persistence call
// without a real SQLite store.
type fakeGrantRecorder struct {
	err   error
	calls []recordedGrant
}

type recordedGrant struct {
	email     string
	nodeID    uint64
	tag       string
	expiresAt time.Time
}

func (f *fakeGrantRecorder) RecordGrant(_ context.Context, email string, nodeID uint64, tag string, expiresAt time.Time) error {
	f.calls = append(f.calls, recordedGrant{email: email, nodeID: nodeID, tag: tag, expiresAt: expiresAt})
	return f.err
}

func newTestHandler(mesh MeshProvisioner) (*Handler, *bytes.Buffer) {
	return newTestHandlerWithGrants(mesh, nil)
}

func newTestHandlerWithGrants(mesh MeshProvisioner, grants GrantRecorder) (*Handler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &Handler{
		Mesh:    mesh,
		Grants:  grants,
		Metrics: &Counters{},
		Logger:  logger,
	}
	return h, &logBuf
}

// Requirement: NM-F-08
func TestHandler_CreateMeshUser(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		createKey      string
		createErr      error
		wantStatus     int
		wantMeshCalled bool
		wantKeyInBody  string
	}{
		{
			name:           "success returns the pre-auth key with 201",
			body:           `{"email":"` + testEmail + `"}`,
			createKey:      "authkey-generated",
			wantStatus:     http.StatusCreated,
			wantMeshCalled: true,
			wantKeyInBody:  "authkey-generated",
		},
		{
			name:       "malformed JSON is rejected with 400, mesh not called",
			body:       `{"email":`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown field is rejected with 400, mesh not called",
			body:       `{"email":"` + testEmail + `","unexpected":"x"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty email is rejected with 400, mesh not called",
			body:       `{"email":""}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed email is rejected with 400, mesh not called",
			body:       `{"email":"not-an-email"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:           "headscale request failure maps to 502",
			body:           `{"email":"` + testEmail + `"}`,
			createErr:      headscale.ErrHeadscaleRequestFailed,
			wantStatus:     http.StatusBadGateway,
			wantMeshCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mesh := &fakeMesh{createKey: tt.createKey, createErr: tt.createErr}
			h, logBuf := newTestHandler(mesh)

			req := httptest.NewRequest(http.MethodPost, MeshUserPath, strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h.CreateMeshUser(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if len(mesh.createCalls) > 0 != tt.wantMeshCalled {
				t.Fatalf("mesh.CreateMeshUser called = %v, want %v", len(mesh.createCalls) > 0, tt.wantMeshCalled)
			}
			if tt.wantKeyInBody != "" {
				var resp meshUserResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if resp.PreAuthKey != tt.wantKeyInBody {
					t.Fatalf("pre_auth_key = %q, want %q", resp.PreAuthKey, tt.wantKeyInBody)
				}
				if !resp.Success {
					t.Fatal("success = false, want true")
				}
			}
			// Zero-trust re-validation failures must never leak the
			// submitted email into the log (mirrors DV-F-20/SS-F-03's
			// "no user-identifying value in the log" pattern, applied
			// here even though no NM-F-* row explicitly names logging).
			if strings.Contains(logBuf.String(), testEmail) && tt.wantStatus == http.StatusBadRequest {
				t.Fatalf("log contains the submitted email: %s", logBuf.String())
			}
		})
	}
}

// Requirement: NM-F-09
func TestHandler_Grant(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		grantErr       error
		wantStatus     int
		wantMeshCalled bool
	}{
		{
			name:           "success returns 200",
			body:           `{"email":"` + testEmail + `","duration_seconds":43200}`,
			wantStatus:     http.StatusOK,
			wantMeshCalled: true,
		},
		{
			name:       "malformed JSON is rejected with 400, mesh not called",
			body:       `{"email":`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty email is rejected with 400, mesh not called",
			body:       `{"email":"","duration_seconds":43200}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:           "mesh user not found maps to 403 (explicit denial)",
			body:           `{"email":"` + testEmail + `","duration_seconds":43200}`,
			grantErr:       headscale.ErrMeshUserNotFound,
			wantStatus:     http.StatusForbidden,
			wantMeshCalled: true,
		},
		{
			name:           "headscale request failure maps to 502",
			body:           `{"email":"` + testEmail + `","duration_seconds":43200}`,
			grantErr:       headscale.ErrHeadscaleRequestFailed,
			wantStatus:     http.StatusBadGateway,
			wantMeshCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mesh := &fakeMesh{grantErr: tt.grantErr}
			h, _ := newTestHandler(mesh)

			req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h.Grant(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if len(mesh.grantCalls) > 0 != tt.wantMeshCalled {
				t.Fatalf("mesh.GrantStorageAccess called = %v, want %v", len(mesh.grantCalls) > 0, tt.wantMeshCalled)
			}
		})
	}
}

// Requirement: NM-F-09
func TestHandler_Grant_IgnoresCallerSuppliedDuration(t *testing.T) {
	// Zero-trust (RNF-SEC-02/03): the wire-compatible duration_seconds
	// field must not influence which email gets granted, or bypass
	// validation - only the mesh.GrantStorageAccess call (which itself
	// uses headscale.GrantDuration, a Network-Manager-owned constant) can
	// determine the real grant length. This test only proves the
	// handler still calls through correctly regardless of what
	// duration_seconds carries; the fixed-12h behavior itself is
	// unit-tested in internal/headscale (TestGrantDuration_Is12Hours).
	mesh := &fakeMesh{}
	h, _ := newTestHandler(mesh)

	body := `{"email":"` + testEmail + `","duration_seconds":999999999}`
	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Grant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if len(mesh.grantCalls) != 1 || mesh.grantCalls[0] != testEmail {
		t.Fatalf("grantCalls = %v, want [%s]", mesh.grantCalls, testEmail)
	}
}

// Requirement: NM-F-11
func TestHandler_Grant_PersistsExpiry(t *testing.T) {
	mesh := &fakeMesh{grantNodeID: 42}
	grants := &fakeGrantRecorder{}
	h, _ := newTestHandlerWithGrants(mesh, grants)

	before := time.Now()
	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(`{"email":"`+testEmail+`"}`))
	w := httptest.NewRecorder()

	h.Grant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if len(grants.calls) != 1 {
		t.Fatalf("RecordGrant called %d times, want 1", len(grants.calls))
	}
	call := grants.calls[0]
	if call.email != testEmail {
		t.Fatalf("RecordGrant email = %q, want %q", call.email, testEmail)
	}
	if call.nodeID != 42 {
		t.Fatalf("RecordGrant nodeID = %d, want 42", call.nodeID)
	}
	if call.tag != headscale.TagStorageAccess {
		t.Fatalf("RecordGrant tag = %q, want %q", call.tag, headscale.TagStorageAccess)
	}
	// NM-F-09's literal "12 hours from that point" - RecordGrant's
	// expiry must reflect the moment the grant actually happened, not a
	// caller-supplied value (same zero-trust reasoning as
	// TestHandler_Grant_IgnoresCallerSuppliedDuration).
	wantExpiry := before.Add(headscale.GrantDuration)
	if call.expiresAt.Before(wantExpiry.Add(-time.Second)) || call.expiresAt.After(wantExpiry.Add(time.Minute)) {
		t.Fatalf("RecordGrant expiresAt = %v, want close to %v", call.expiresAt, wantExpiry)
	}
}

// Requirement: NM-F-11
func TestHandler_Grant_PersistenceFailureStillReturnsSuccess(t *testing.T) {
	// A durability-layer failure must not turn an already-successful
	// Headscale reachability grant into a client-visible failure - see
	// Handler.Grant's own doc comment for the reasoning.
	mesh := &fakeMesh{grantNodeID: 42}
	grants := &fakeGrantRecorder{err: errors.New("disk full")}
	h, logBuf := newTestHandlerWithGrants(mesh, grants)

	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(`{"email":"`+testEmail+`"}`))
	w := httptest.NewRecorder()

	h.Grant(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "NM-F-11") {
		t.Fatalf("expected the persistence failure to be logged loudly, log=%s", logBuf.String())
	}
}

// Requirement: NM-F-09
func TestGrantResponse_WireCompatibleWithSecuritySwitch(t *testing.T) {
	// Security-Switch's networkmanager.grantRequest/grantResponse
	// (already committed, not this task's file to edit) must decode
	// what this handler writes without any field-name mismatch.
	mesh := &fakeMesh{}
	h, _ := newTestHandler(mesh)

	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(
		`{"email":"`+testEmail+`","duration_seconds":43200}`,
	))
	w := httptest.NewRecorder()
	h.Grant(w, req)

	var parsed struct {
		Success bool   `json:"success"`
		Error   string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !parsed.Success {
		t.Fatalf("success = false, want true (body=%s)", w.Body.String())
	}
}
