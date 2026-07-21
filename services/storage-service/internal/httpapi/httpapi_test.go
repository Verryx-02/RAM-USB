package httpapi_test

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

	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/httpapi"
)

// fakeCreator is a hand-written UserCreator fake (CONTRIBUTING.md §7.5):
// it records the username it was asked to create and returns whatever
// error (if any) the test configured.
type fakeCreator struct {
	err          error
	gotUsername  string
	createCalled bool
}

func (f *fakeCreator) CreateUser(_ context.Context, username string) error {
	f.createCalled = true
	f.gotUsername = username
	return f.err
}

// decodedResponse mirrors createUserResponse's wire shape, decoded
// independently in the test so an assertion failure points at a real JSON
// contract mismatch, not at reuse of the package's own (private) type.
type decodedResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Requirement: ST-F-06
// Requirement: ST-F-10
func TestHandler_CreateUser(t *testing.T) {
	const validUsername = "user7g3k9z"

	tests := []struct {
		name           string
		body           string
		creatorErr     error
		wantStatus     int
		wantSuccess    bool
		wantCreateCall bool
	}{
		{
			name:           "successful creation reports success and 201",
			body:           `{"username":"` + validUsername + `"}`,
			creatorErr:     nil,
			wantStatus:     http.StatusCreated,
			wantSuccess:    true,
			wantCreateCall: true,
		},
		{
			name:           "creation failure reports failure without leaking detail",
			body:           `{"username":"` + validUsername + `"}`,
			creatorErr:     errors.New("useradd: some sensitive system detail"),
			wantStatus:     http.StatusInternalServerError,
			wantSuccess:    false,
			wantCreateCall: true,
		},
		{
			name:           "malformed JSON body is rejected before calling the creator",
			body:           `{"username":`,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantCreateCall: false,
		},
		{
			name:           "unknown field is rejected before calling the creator",
			body:           `{"username":"` + validUsername + `","extra":"field"}`,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantCreateCall: false,
		},
		{
			name:           "empty username is rejected before calling the creator",
			body:           `{"username":""}`,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantCreateCall: false,
		},
		{
			name:           "malformed username shape is rejected before calling the creator",
			body:           `{"username":"not-a-valid-username"}`,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantCreateCall: false,
		},
		{
			name:           "uppercase username is rejected before calling the creator",
			body:           `{"username":"USER7G3K9Z"}`,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantCreateCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creator := &fakeCreator{err: tt.creatorErr}
			var logBuf bytes.Buffer
			h := &httpapi.Handler{
				Creator: creator,
				Logger:  slog.New(slog.NewTextHandler(&logBuf, nil)),
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.CreateUserPath, strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			h.CreateUser(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var got decodedResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("response body did not decode as the expected contract: %v (body=%q)", err, rec.Body.String())
			}

			if got.Success != tt.wantSuccess {
				t.Fatalf("success = %v, want %v", got.Success, tt.wantSuccess)
			}

			if !tt.wantSuccess && got.Error == "" {
				t.Fatalf("error field empty on a failure response, want a public message")
			}
			if tt.wantSuccess && got.Error != "" {
				t.Fatalf("error field = %q on a success response, want empty (omitempty)", got.Error)
			}

			if creator.createCalled != tt.wantCreateCall {
				t.Fatalf("creator called = %v, want %v", creator.createCalled, tt.wantCreateCall)
			}

			if tt.wantCreateCall && creator.gotUsername != validUsername {
				t.Fatalf("creator received username %q, want %q", creator.gotUsername, validUsername)
			}

			if tt.creatorErr != nil && strings.Contains(rec.Body.String(), tt.creatorErr.Error()) {
				t.Fatalf("response body leaked internal error detail: %q", rec.Body.String())
			}
			if tt.creatorErr != nil && strings.Contains(logBuf.String(), "some sensitive system detail") == false {
				t.Fatalf("expected internal error detail to be present in the log for operator visibility")
			}
		})
	}
}

// Requirement: ST-F-10
func TestHandler_CreateUser_ResponseShapeMatchesDatabaseVaultContract(t *testing.T) {
	// Cross-check: this is the exact struct shape
	// database-vault/internal/posix's unexported createUserResponse
	// parses (json:"success", json:"error,omitempty"), reproduced here
	// deliberately (not imported - Go's internal-package rule prevents
	// that) so a contract drift between the two sides shows up as a
	// failing test on this side too.
	creator := &fakeCreator{}
	h := &httpapi.Handler{Creator: creator}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, httpapi.CreateUserPath, strings.NewReader(`{"username":"user7g3k9z"}`))
	rec := httptest.NewRecorder()

	h.CreateUser(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if _, ok := raw["success"]; !ok {
		t.Fatalf("response body missing \"success\" field: %q", rec.Body.String())
	}
	if _, ok := raw["error"]; ok {
		t.Fatalf("response body has an \"error\" field on success, want it omitted: %q", rec.Body.String())
	}
}
