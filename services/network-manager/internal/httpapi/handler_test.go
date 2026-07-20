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
	createKeyID uint64
	createErr   error
	grantErr    error
	grantNodeID uint64
	createCalls []string
	grantCalls  []uint64
}

func (f *fakeMesh) CreateMeshUser(_ context.Context, email string) (string, uint64, error) {
	f.createCalls = append(f.createCalls, email)
	if f.createErr != nil {
		return "", 0, f.createErr
	}
	return f.createKey, f.createKeyID, nil
}

func (f *fakeMesh) GrantStorageAccess(_ context.Context, preAuthKeyID uint64) (uint64, error) {
	f.grantCalls = append(f.grantCalls, preAuthKeyID)
	if f.grantErr != nil {
		return 0, f.grantErr
	}
	return f.grantNodeID, nil
}

// fakeMeshUserStore is a hand-written fake implementing MeshUserStore
// (CONTRIBUTING.md §7.5), letting tests assert the new persisted
// email -> pre-auth-key-ID mapping without a real SQLite store.
type fakeMeshUserStore struct {
	recordErr error
	lookupErr error
	// keyIDs simulates rows already persisted (e.g. by an earlier
	// CreateMeshUser call) before the test's Grant call runs.
	keyIDs map[string]uint64

	recordCalls []recordedPreAuthKeyID
	lookupCalls []string
}

type recordedPreAuthKeyID struct {
	email        string
	preAuthKeyID uint64
}

func (f *fakeMeshUserStore) RecordPreAuthKeyID(_ context.Context, email string, preAuthKeyID uint64) error {
	f.recordCalls = append(f.recordCalls, recordedPreAuthKeyID{email: email, preAuthKeyID: preAuthKeyID})
	if f.recordErr != nil {
		return f.recordErr
	}
	if f.keyIDs == nil {
		f.keyIDs = make(map[string]uint64)
	}
	f.keyIDs[email] = preAuthKeyID
	return nil
}

func (f *fakeMeshUserStore) PreAuthKeyIDForEmail(_ context.Context, email string) (uint64, bool, error) {
	f.lookupCalls = append(f.lookupCalls, email)
	if f.lookupErr != nil {
		return 0, false, f.lookupErr
	}
	id, ok := f.keyIDs[email]
	return id, ok, nil
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

// newTestHandler wires a Handler with a MeshUsers store pre-populated with
// testEmail -> a fixed pre-auth-key ID, so Grant's new
// PreAuthKeyIDForEmail lookup succeeds by default for every test that
// exercises Grant against testEmail without caring about the mapping
// itself (see TestHandler_MeshUsersLookup* below for tests that do).
func newTestHandler(mesh MeshProvisioner) (*Handler, *bytes.Buffer) {
	return newTestHandlerFull(mesh, nil, defaultMeshUserStore())
}

func newTestHandlerWithGrants(mesh MeshProvisioner, grants GrantRecorder) (*Handler, *bytes.Buffer) {
	return newTestHandlerFull(mesh, grants, defaultMeshUserStore())
}

func newTestHandlerFull(mesh MeshProvisioner, grants GrantRecorder, meshUsers MeshUserStore) (*Handler, *bytes.Buffer) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := &Handler{
		Mesh:      mesh,
		Grants:    grants,
		MeshUsers: meshUsers,
		Metrics:   &Counters{},
		Logger:    logger,
	}
	return h, &logBuf
}

// defaultMeshUserStoreKeyID is the pre-auth-key ID newTestHandler's default
// MeshUsers store already has on record for testEmail.
const defaultMeshUserStoreKeyID = 7

func defaultMeshUserStore() *fakeMeshUserStore {
	return &fakeMeshUserStore{keyIDs: map[string]uint64{testEmail: defaultMeshUserStoreKeyID}}
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

// Requirement: NM-F-08
//
// Proves the new persistence step this fix introduces: after a successful
// Headscale call, the generated pre-auth key's numeric ID must be recorded
// against the submitted email via h.MeshUsers, since that is the only
// thing GrantStorageAccess can use to find this user's node at any future
// login.
func TestHandler_CreateMeshUser_PersistsPreAuthKeyID(t *testing.T) {
	mesh := &fakeMesh{createKey: "authkey-generated", createKeyID: 99}
	meshUsers := &fakeMeshUserStore{}
	h, _ := newTestHandlerFull(mesh, nil, meshUsers)

	req := httptest.NewRequest(http.MethodPost, MeshUserPath, strings.NewReader(`{"email":"`+testEmail+`"}`))
	w := httptest.NewRecorder()

	h.CreateMeshUser(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", w.Code, w.Body.String())
	}
	if len(meshUsers.recordCalls) != 1 {
		t.Fatalf("RecordPreAuthKeyID called %d times, want 1", len(meshUsers.recordCalls))
	}
	call := meshUsers.recordCalls[0]
	if call.email != testEmail || call.preAuthKeyID != 99 {
		t.Fatalf("RecordPreAuthKeyID call = %+v, want email=%s preAuthKeyID=99", call, testEmail)
	}
}

// Requirement: NM-F-08
//
// Unlike NM-F-11's grant-expiry persistence (best-effort, logged loudly
// but does not fail the request), a MeshUsers persistence failure here
// must fail the whole request: without this row, every future login for
// this account would fail forever, silently, if this handler reported
// success anyway.
func TestHandler_CreateMeshUser_PersistenceFailureFailsTheRequest(t *testing.T) {
	mesh := &fakeMesh{createKey: "authkey-generated", createKeyID: 99}
	meshUsers := &fakeMeshUserStore{recordErr: errors.New("disk full")}
	h, logBuf := newTestHandlerFull(mesh, nil, meshUsers)

	req := httptest.NewRequest(http.MethodPost, MeshUserPath, strings.NewReader(`{"email":"`+testEmail+`"}`))
	w := httptest.NewRecorder()

	h.CreateMeshUser(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "every future login") {
		t.Fatalf("expected the fatal persistence failure to be logged clearly, log=%s", logBuf.String())
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
//
// This is the handler-level proof of the bug fix's fail-secure path: an
// email with no persisted pre-auth-key-ID row (e.g. never registered
// through NM-F-08) must be denied with the same 403 ErrMeshUserNotFound
// response Headscale itself would produce - h.Mesh.GrantStorageAccess must
// never even be called, since there is no ID to pass it.
func TestHandler_Grant_NoPreAuthKeyIDRecorded_Denies(t *testing.T) {
	mesh := &fakeMesh{}
	meshUsers := &fakeMeshUserStore{} // empty: no row for testEmail
	h, _ := newTestHandlerFull(mesh, nil, meshUsers)

	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(`{"email":"`+testEmail+`","duration_seconds":43200}`))
	w := httptest.NewRecorder()

	h.Grant(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if len(mesh.grantCalls) != 0 {
		t.Fatalf("mesh.GrantStorageAccess called %d times, want 0 (no pre-auth key id to pass it)", len(mesh.grantCalls))
	}
	if len(meshUsers.lookupCalls) != 1 || meshUsers.lookupCalls[0] != testEmail {
		t.Fatalf("MeshUsers.PreAuthKeyIDForEmail calls = %v, want [%s]", meshUsers.lookupCalls, testEmail)
	}
}

// Requirement: NM-F-09
func TestHandler_Grant_MeshUsersLookupFailure_Returns500(t *testing.T) {
	mesh := &fakeMesh{}
	meshUsers := &fakeMeshUserStore{lookupErr: errors.New("disk error")}
	h, _ := newTestHandlerFull(mesh, nil, meshUsers)

	req := httptest.NewRequest(http.MethodPost, GrantPath, strings.NewReader(`{"email":"`+testEmail+`","duration_seconds":43200}`))
	w := httptest.NewRecorder()

	h.Grant(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%s)", w.Code, w.Body.String())
	}
	if len(mesh.grantCalls) != 0 {
		t.Fatalf("mesh.GrantStorageAccess called %d times, want 0", len(mesh.grantCalls))
	}
}

// Requirement: NM-F-09
func TestHandler_Grant_IgnoresCallerSuppliedDuration(t *testing.T) {
	// Zero-trust (RNF-SEC-02/03): the wire-compatible duration_seconds
	// field must not influence which pre-auth-key ID gets granted, or
	// bypass validation - only the mesh.GrantStorageAccess call (which
	// itself uses headscale.GrantDuration, a Network-Manager-owned
	// constant) can determine the real grant length. This test only
	// proves the handler still calls through correctly regardless of
	// what duration_seconds carries; the fixed-12h behavior itself is
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
	if len(mesh.grantCalls) != 1 || mesh.grantCalls[0] != defaultMeshUserStoreKeyID {
		t.Fatalf("grantCalls = %v, want [%d]", mesh.grantCalls, defaultMeshUserStoreKeyID)
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
