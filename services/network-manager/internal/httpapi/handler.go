// Package httpapi wires Network-Manager's internal/headscale package into
// the two HTTP handlers Security-Switch calls (NM-F-08, NM-F-09), over the
// mTLS listener internal/server (NM-F-03) configures.
//
// MeshUserPath is this session's invented, documented contract for
// NM-F-08 - Security-Switch has no code yet calling it (the task that
// built this handler explicitly excludes wiring Security-Switch's
// registration flow to call it; that is a separate follow-up task once
// this contract is confirmed). GrantPath, by contrast, is NOT invented
// here: it reproduces, field-for-field, the already-committed contract
// services/security-switch/internal/networkmanager/client.go (SS-F-05)
// expects - {"email":"...", "duration_seconds": ...} in,
// {"success":bool,"error":"...,omitempty"} out, 200/201 on success, 403 on
// explicit denial. This handler's Grant must keep matching that file
// exactly; if it ever needs to change, change both sides by hand (no
// shared type exists across these two services' internal packages, the
// same Go internal-package limitation already documented for
// Storage-Service's httpapi vs. Database-Vault's posix package).
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"time"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// MeshUserPath and GrantPath are Network-Manager's own internal endpoint
// paths. See the package doc comment: MeshUserPath is invented for this
// task; GrantPath reproduces Security-Switch's already-fixed contract
// exactly.
const (
	MeshUserPath = "/internal/v1/mesh-users"
	GrantPath    = "/internal/v1/grants"
)

// maxRequestBodyBytes bounds both handlers' request bodies. Both payloads
// are a handful of short fields (an email, optionally a duration) - no
// SRS figure exists for this limit, chosen the same way Storage-Service's
// ST-F-06 handler chose its own 4 KiB bound: generous relative to the
// payload's real shape, not a value with any other significance.
const maxRequestBodyBytes = 4 * 1024

// Handler ties Network-Manager's mesh-provisioning logic (internal/
// headscale) to its HTTP boundary.
type Handler struct {
	// Mesh performs the real Headscale operations (NM-F-08, NM-F-09),
	// typically a HeadscaleAdapter wrapping a headscale.Service backed by
	// a real gRPC connection (headscale.Dial). Must not be nil.
	Mesh MeshProvisioner

	// Grants persists NM-F-09's grant (NM-F-11: node, tag, expiry) so
	// NM-F-10's sweep survives a Network-Manager restart. If nil, Grant
	// still performs the real Headscale reachability grant but skips
	// persistence, logging that fact loudly - see Grant's own doc
	// comment for why a persistence failure does not itself fail the
	// request.
	Grants GrantRecorder

	// MeshUsers persists (CreateMeshUser) and looks up (Grant) the
	// permanent email -> Headscale-pre-auth-key-ID mapping this fix
	// introduces (see internal/headscale/client.go's "Bug fix" section
	// and internal/grants' package doc comment). Must not be nil -
	// unlike Grants above, there is no meaningful degraded mode: without
	// this store, GrantStorageAccess has no way to find a user's mesh
	// node at all, ever.
	MeshUsers MeshUserStore

	// Metrics accumulates request/error/response-time counts feeding
	// NM-F-17/NM-F-18's periodic MQTT publish (pkg/metrics.Run, wired in
	// cmd/network-manager/main.go). Must not be nil - same
	// "always required, wired by every constructor" convention as
	// Database-Vault's own Handler.Metrics.
	Metrics *Counters

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used - same injectable-logger pattern as
	// Database-Vault's DV-F-20 handler and Security-Switch's SS-F-03
	// handler, letting tests assert no email is written to the log.
	Logger *slog.Logger
}

func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// meshUserRequest is the JSON body Security-Switch sends to request a
// dedicated Headscale user + pre-auth key (NM-F-08), once wired (out of
// this task's scope). Only the email is needed: Network-Manager derives
// its own Headscale username (internal/headscale.meshUsername) - it does
// not accept one from the caller.
type meshUserRequest struct {
	Email string `json:"email"`
}

// meshUserResponse is the JSON body CreateMeshUser writes.
type meshUserResponse struct {
	Success    bool   `json:"success"`
	PreAuthKey string `json:"pre_auth_key,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CreateMeshUser implements NM-F-08's receiving side: on request from
// Security-Switch, following successful registration, create a dedicated
// Headscale user and a short-lived pre-auth key for the new account. The
// key travels back in the response - per UC-01 step 7-8, Security-Switch
// relays it all the way back to the client, the one credential in this
// codebase that does so.
//
// After the real Headscale call succeeds, the generated pre-auth key's
// numeric ID is persisted against email via h.MeshUsers (NM-F-09 needs it
// at every future login - see MeshUserStore's own doc comment). Unlike
// Grant's NM-F-11 persistence below, a MeshUsers failure here fails the
// whole request (500): the Headscale side already succeeded, but without
// this row GrantStorageAccess can never find this user's node again, at
// any future login, for the lifetime of the account - reporting success
// to the caller would be actively misleading, not merely a durability
// nicety. This does leave the just-created Headscale user/pre-auth key
// orphaned in that failure case; cleaning that up is an operational
// concern out of this fix's scope, not something RD-04's fail-secure
// principle requires undoing here.
func (h *Handler) CreateMeshUser(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.Metrics.BeginRequest()
	isError := false
	defer func() {
		h.Metrics.EndRequest(time.Since(start), isError)
	}()

	req, err := decodeMeshUserRequest(r.Body)
	if err != nil {
		isError = true
		h.logger().Warn("mesh-user creation: decode failed", "endpoint", "mesh-users", "error", err)
		writeAppError(w, apperrors.NewBadRequest(err))
		return
	}

	if err := validateEmail(req.Email); err != nil {
		isError = true
		h.logger().Warn("mesh-user creation: validation failed", "endpoint", "mesh-users", "error", err)
		writeAppError(w, apperrors.NewBadRequest(err))
		return
	}

	key, preAuthKeyID, err := h.Mesh.CreateMeshUser(r.Context(), req.Email)
	if err != nil {
		isError = true
		h.logger().Error("mesh-user creation: headscale call failed", "error", err)
		writeAppError(w, mapHeadscaleError(err))
		return
	}

	if err := h.MeshUsers.RecordPreAuthKeyID(r.Context(), req.Email, preAuthKeyID); err != nil {
		isError = true
		h.logger().Error("mesh-user creation: failed to persist pre-auth key id mapping, every future login for this account will fail", "error", err)
		writeAppError(w, apperrors.NewInternal(err))
		return
	}

	h.logger().Info("mesh-user creation: succeeded")
	writeJSON(w, http.StatusCreated, meshUserResponse{Success: true, PreAuthKey: key})
}

// grantRequest is the JSON body Security-Switch sends
// (services/security-switch/internal/networkmanager/client.go's
// grantRequest) - field names and shape must match that file exactly.
type grantRequest struct {
	Email           string `json:"email"`
	DurationSeconds int64  `json:"duration_seconds"`
}

// grantResponse is the JSON body Grant writes
// (services/security-switch/internal/networkmanager/client.go's
// grantResponse) - field names and shape must match that file exactly.
type grantResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Grant implements NM-F-09's receiving side: after a successful login, on
// request from Security-Switch, assign the user's already-existing mesh
// node the ACL tag enabling reachability toward Storage-Service.
//
// The node is found by first looking up email's persisted Headscale
// pre-auth-key ID via h.MeshUsers (recorded by CreateMeshUser at
// registration time), then passing that ID into h.Mesh.GrantStorageAccess
// - not by looking the user up in Headscale directly. See
// internal/headscale/client.go's package doc comment ("Bug fix" section)
// for the full root cause this replaced: Headscale's own per-user node
// ownership cannot be used for this lookup, because every node this
// package creates registers via a tagged pre-auth key and is therefore
// owned by Headscale's synthetic "tagged-devices" pseudo-user, never by
// the specific per-user account. A missing MeshUsers row (email never
// registered through NM-F-08, or its persistence failed at registration
// time) is treated identically to Headscale reporting no matching node -
// the same 403 ErrMeshUserNotFound denial, RD-04 fail-secure, no
// distinguishing detail leaked either way.
//
// DurationSeconds in the request is decoded but deliberately NOT used to
// compute the actual grant window: NM-F-09's literal text fixes the
// expiry at "12 hours from that point" as Network-Manager's own decision,
// and RNF-SEC-02/03's zero-trust principle means Network-Manager must not
// let an already-authenticated caller dictate how long a security-
// sensitive grant lasts. internal/headscale.GrantDuration (a Network-
// Manager-owned constant, currently also 12h, matching Security-Switch's
// own SS-F-05 constant by coincidence of both being correctly read off
// the same requirement) is the only value that governs the real grant;
// this field exists purely for wire-contract compatibility with
// Security-Switch's already-committed client.
func (h *Handler) Grant(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.Metrics.BeginRequest()
	isError := false
	defer func() {
		h.Metrics.EndRequest(time.Since(start), isError)
	}()

	req, err := decodeGrantRequest(r.Body)
	if err != nil {
		isError = true
		h.logger().Warn("grant: decode failed", "endpoint", "grants", "error", err)
		writeAppError(w, apperrors.NewBadRequest(err))
		return
	}

	if err := validateEmail(req.Email); err != nil {
		isError = true
		h.logger().Warn("grant: validation failed", "endpoint", "grants", "error", err)
		writeAppError(w, apperrors.NewBadRequest(err))
		return
	}

	preAuthKeyID, found, err := h.MeshUsers.PreAuthKeyIDForEmail(r.Context(), req.Email)
	if err != nil {
		isError = true
		h.logger().Error("grant: failed to look up pre-auth key id", "error", err)
		writeAppError(w, apperrors.NewInternal(err))
		return
	}
	if !found {
		isError = true
		h.logger().Warn("grant: no pre-auth key id recorded for this email, denying")
		writeAppError(w, mapHeadscaleError(headscale.ErrMeshUserNotFound))
		return
	}

	nodeID, err := h.Mesh.GrantStorageAccess(r.Context(), preAuthKeyID)
	if err != nil {
		isError = true
		h.logger().Error("grant: headscale call failed", "error", err)
		writeAppError(w, mapHeadscaleError(err))
		return
	}

	// NM-F-11: persist the grant's expiry so NM-F-10's sweep can find and
	// revoke it even across a Network-Manager restart. The real
	// reachability grant above already succeeded - a persistence
	// failure here is an operational/durability problem (the grant
	// might outlive GrantDuration if the sweep never learns about it),
	// not a reason to tell the caller the grant itself failed, so it is
	// logged loudly rather than turned into a 5xx response. Nil Grants
	// (no store configured) is treated the same way, loudly, not
	// silently - see the Handler field's own doc comment.
	if h.Grants == nil {
		h.logger().Error("grant: no grant store configured, NM-F-11 persistence skipped", "node_id", nodeID)
	} else if err := h.Grants.RecordGrant(r.Context(), req.Email, nodeID, headscale.TagStorageAccess, time.Now().Add(headscale.GrantDuration)); err != nil {
		h.logger().Error("grant: failed to persist grant expiry (NM-F-11)", "node_id", nodeID, "error", err)
	}

	h.logger().Info("grant: succeeded")
	writeJSON(w, http.StatusOK, grantResponse{Success: true})
}

// mapHeadscaleError maps internal/headscale's sentinel errors to an
// HTTP status: ErrMeshUserNotFound is an explicit denial (403, the same
// status Security-Switch's client already recognizes as
// ErrGrantDenied) since there is no node to act on; any other
// ErrHeadscaleRequestFailed means the call to Headscale itself did not
// succeed (502, a downstream-dependency failure); anything else falls
// back to 500.
//
// Known gap, flagged rather than silently worked around: Security-
// Switch's own already-committed GrantAccess client
// (networkmanager/client.go) only distinguishes a literal HTTP 403 as
// ErrGrantDenied - any other non-200/201 status this handler returns
// (502, 500) is *also* folded into Security-Switch's own ErrGrantDenied
// by its generic "any other status" branch, not into
// ErrNetworkManagerUnreachable/ErrNetworkManagerTimeout as its own doc
// comments might suggest. This handler still returns semantically
// correct status codes; the mismatch is on Security-Switch's client
// side, out of this task's file-ownership scope to fix.
func mapHeadscaleError(err error) *apperrors.AppError {
	switch {
	case errors.Is(err, headscale.ErrMeshUserNotFound):
		return apperrors.NewForbidden(err)
	case errors.Is(err, headscale.ErrHeadscaleRequestFailed):
		return apperrors.NewBadGateway(err)
	default:
		return apperrors.NewInternal(err)
	}
}

// validateEmail is NM-F-08/NM-F-09's own independent, zero-trust re-check
// (RNF-SEC-02/03) of the one field either request carries: present, and
// RFC 5322-parseable. Deliberately a package-local check, not a call into
// pkg/validation - that package's validateEmail is unexported and its
// exported entry points (ValidateRegister/ValidateLogin) require a
// password too, which neither of these two payloads carries.
func validateEmail(email string) error {
	if email == "" {
		return errEmailRequired
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errEmailInvalid
	}
	return nil
}

var (
	errEmailRequired = errors.New("network-manager: email is required")
	errEmailInvalid  = errors.New("network-manager: email is not a valid address")
)

func decodeMeshUserRequest(r io.Reader) (meshUserRequest, error) {
	var req meshUserRequest
	if err := decodeJSON(r, &req); err != nil {
		return meshUserRequest{}, err
	}
	return req, nil
}

func decodeGrantRequest(r io.Reader) (grantRequest, error) {
	var req grantRequest
	if err := decodeJSON(r, &req); err != nil {
		return grantRequest{}, err
	}
	return req, nil
}

// decodeJSON bounds the request body (maxRequestBodyBytes) and rejects
// unknown fields, the same decoding-boundary discipline pkg/validation
// already applies to Entry-Hub/Security-Switch/Database-Vault's payloads.
func decodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r, maxRequestBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errMalformedRequest
	}
	return nil
}

var errMalformedRequest = errors.New("network-manager: malformed request body")

// appErrorResponse is the JSON body written for a decode/validation
// failure: only the AppError's Public message, never its Internal detail.
type appErrorResponse struct {
	Error string `json:"error"`
}

func writeAppError(w http.ResponseWriter, appErr *apperrors.AppError) {
	writeJSON(w, appErr.Status, appErrorResponse{Error: appErr.Public})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
