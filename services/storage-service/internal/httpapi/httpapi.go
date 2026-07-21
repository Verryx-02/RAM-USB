// Package httpapi implements Storage-Service's HTTP-receiving side of the
// POSIX-user-creation request Database-Vault sends over mTLS (ST-F-06), and
// reports the outcome back in the HTTP response (ST-F-10).
//
// The JSON contract here is not invented by this package: it must match
// exactly what Database-Vault's DV-F-09 client
// (services/database-vault/internal/posix/client.go) already sends and
// expects to parse. CreateUserPath, createUserRequest, and
// createUserResponse are this package's own copies of that same contract
// (Go's internal-package import rule means this package cannot import
// database-vault's internal/posix directly, even though both services live
// in the same module) — if that contract ever changes, both sides must be
// updated together.
//
// Actually creating the POSIX user on the underlying OS (useradd, chroot,
// sshd configuration — ST-F-07/ST-F-08/ST-F-09) is deliberately out of
// scope for this package. It is abstracted behind the UserCreator
// interface so this HTTP boundary can be built and tested now; a real
// implementation is a separate, security-sensitive task (it must get the
// chroot/no-shell/no-home-directory/no-password requirements exactly
// right) that needs its own design discussion before being written.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// CreateUserPath is the HTTP endpoint Database-Vault calls on
// Storage-Service to request POSIX-user creation (DV-F-09/ST-F-06). Must
// stay identical to database-vault/internal/posix.CreateUserPath.
const CreateUserPath = "/internal/v1/posix-users"

// maxRequestBodyBytes bounds the size of an incoming request body before
// decoding, per RNF-SEC-02/03's zero-trust re-validation (every layer
// re-validates input independently, even from an already-authenticated
// mTLS caller). The only expected field is a short fixed-format username
// (see usernamePattern), so this is a generous but still bounded ceiling,
// this session's judgment call in the absence of any SRS-specified figure.
const maxRequestBodyBytes = 4 * 1024

// usernamePattern matches exactly the username shape ST-F-06 specifies:
// "user" followed by 6 lowercase base-36 characters (0-9, a-z). Database-
// Vault's DV-F-09 already generates usernames in this shape, but this
// handler re-validates it independently rather than trusting the caller,
// per RNF-SEC-02/03 and RD-04 (fail-secure on any uncertainty).
var usernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// ErrMalformedRequestBody means the request body could not be decoded as
// the expected JSON shape (unreadable, too large, invalid JSON, or an
// unexpected field set).
var ErrMalformedRequestBody = errors.New("httpapi: malformed create-user request body")

// ErrInvalidUsername means the request decoded successfully but its
// username field does not match usernamePattern.
var ErrInvalidUsername = errors.New("httpapi: username does not match the required format")

// UserCreator abstracts the actual POSIX-user-creation step (ST-F-07
// through ST-F-09's OS-level work), so this HTTP boundary (ST-F-06,
// ST-F-10) can be implemented and tested without it. A production
// implementation is a separate, not-yet-built task; see the package doc
// comment.
type UserCreator interface {
	// CreateUser creates a POSIX user named username on the underlying
	// system. A nil return means the user was created successfully.
	CreateUser(ctx context.Context, username string) error
}

// createUserRequest is the JSON body Database-Vault sends (DV-F-09). Must
// stay identical in shape to database-vault/internal/posix's
// createUserRequest.
type createUserRequest struct {
	Username string `json:"username"`
}

// createUserResponse is the JSON body this handler sends back, reporting
// the outcome of POSIX-user creation (ST-F-10). Must stay identical in
// shape to database-vault/internal/posix's createUserResponse: Error is
// omitted entirely on success, never populated alongside Success=true.
type createUserResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Handler wires UserCreator to net/http for ST-F-06/ST-F-10.
type Handler struct {
	// Creator performs the actual POSIX-user creation. Must not be nil.
	Creator UserCreator

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used.
	Logger *slog.Logger
}

// logger returns h.Logger, or slog.Default() if unset.
func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// CreateUser handles POST CreateUserPath: decode and re-validate the
// request (RNF-SEC-02/03), call h.Creator (ST-F-06), and report the
// outcome back in the response (ST-F-10). Every response, success or
// failure, is a createUserResponse; the request is never forwarded or
// retried past a validation failure (RD-04, fail-secure).
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	req, err := decodeCreateUserRequest(r)
	if err != nil {
		// err's formatted string can embed the request body's own content
		// (encoding/json's DisallowUnknownFields error echoes back the
		// offending field name verbatim, for instance) - Sanitize keeps
		// that content out of the way of the log stream's own structure
		// (RNF-SEC-02/RNF-SEC-03), independent of whatever validation ran
		// upstream of this handler.
		h.logger().Warn("create-user: request rejected", "error", logging.Sanitize(err.Error()))
		writeResult(w, apperrors.NewBadRequest(err))
		return
	}

	if !usernamePattern.MatchString(req.Username) {
		h.logger().Warn("create-user: request rejected", "error", ErrInvalidUsername)
		writeResult(w, apperrors.NewBadRequest(ErrInvalidUsername))
		return
	}

	if err := h.Creator.CreateUser(r.Context(), req.Username); err != nil {
		h.logger().Error("create-user: POSIX user creation failed", "error", logging.Sanitize(err.Error()))
		writeResult(w, apperrors.NewInternal(err))
		return
	}

	h.logger().Info("create-user: POSIX user created")
	writeJSON(w, http.StatusCreated, createUserResponse{Success: true})
}

// decodeCreateUserRequest reads and decodes r's body as a createUserRequest,
// bounding its size and rejecting unknown fields (RNF-SEC-02/03).
func decodeCreateUserRequest(r *http.Request) (createUserRequest, error) {
	body := http.MaxBytesReader(nil, r.Body, maxRequestBodyBytes)

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()

	var req createUserRequest
	if err := decoder.Decode(&req); err != nil {
		return createUserRequest{}, errors.Join(ErrMalformedRequestBody, err)
	}

	if req.Username == "" {
		return createUserRequest{}, ErrMalformedRequestBody
	}

	return req, nil
}

// writeResult writes appErr.Status with a createUserResponse body carrying
// success=false and appErr's fixed public message — never appErr.Internal,
// which stays in the log line the caller already wrote, per pkg/errors's
// no-detail-leak convention (ST-F-* per CONTRIBUTING.md §7.3).
func writeResult(w http.ResponseWriter, appErr *apperrors.AppError) {
	writeJSON(w, appErr.Status, createUserResponse{Success: false, Error: appErr.Public})
}

// writeJSON writes status and body, JSON-encoded, to w.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
