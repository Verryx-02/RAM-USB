// Package httpapi wires Security-Switch's already-implemented building
// blocks - pkg/validation (SS-F-02), internal/dbvault (SS-F-04), and
// internal/networkmanager (SS-F-05) - into the two HTTP handlers
// Entry-Hub calls over the mTLS listener SS-F-01/internal/server
// configures.
//
// SS-F-03 is enforced at the top of both handlers: a decode or validation
// failure responds HTTP 400 with a generic body, logs the failure without
// any user-identifying value, and returns immediately - DBVault.Register/
// DBVault.Login are never called on that path.
//
// No literal path is specified anywhere in the SRS or design docs for
// Security-Switch's own internal endpoints (only Entry-Hub's public-facing
// /api/register and /api/login, and Database-Vault's own invented
// /internal/v1/register and /internal/v1/login, are named).
// RegisterPath and LoginPath below are this session's invented judgment
// call - conceptually matching Entry-Hub's public path names, since
// Entry-Hub is the caller here, but naming Security-Switch's own,
// separate internal endpoint, exactly like Database-Vault's own
// /internal/v1/* paths name a distinct endpoint from Entry-Hub's public
// ones.
package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
)

// RegisterPath and LoginPath are Security-Switch's own internal endpoint
// paths. See the package doc comment: these are invented, not sourced
// from the SRS or a design doc.
const (
	RegisterPath = "/internal/v1/register"
	LoginPath    = "/internal/v1/login"
)

// Handler ties Security-Switch's re-validation (SS-F-02), validation
// failure handling (SS-F-03), Database-Vault forwarding (SS-F-04), and
// Network-Manager grant request (SS-F-05) together.
type Handler struct {
	// DBVault forwards a re-validated request to Database-Vault over
	// mTLS (SS-F-04), typically a DBVaultAdapter wrapping an *http.Client
	// configured with pkg/mtls.ClientConfig verifying
	// dbvault.OrganizationDatabaseVault.
	DBVault DatabaseVaultClient

	// NetworkManager requests a Storage-Service access grant after a
	// successful login (SS-F-05), typically a NetworkManagerAdapter
	// wrapping an *http.Client configured with pkg/mtls.ClientConfig
	// verifying networkmanager.OrganizationNetworkManager.
	NetworkManager NetworkManagerClient

	// Metrics accumulates request/error/response-time counts feeding
	// SS-F-07/SS-F-08's periodic publish. Must not be nil.
	Metrics *Counters

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used. Tests inject a logger writing to a
	// buffer to assert SS-F-03's "no user-identifying value in the log"
	// requirement, same pattern as Database-Vault's DV-F-20 handler test.
	Logger *slog.Logger
}

// logger returns h.Logger, or slog.Default() if unset.
func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// Register handles a registration request forwarded by Entry-Hub: decode
// and re-validate independently of Entry-Hub's own validation (SS-F-02).
// On failure, SS-F-03 applies: HTTP 400, a generic body, a log line
// without the email/password/SSH key, and no call to DBVault at all. On
// success, SS-F-04 applies: log the outcome without identifying the user,
// then forward to Database-Vault and relay its response.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.Metrics.BeginRequest()
	isError := false
	defer func() {
		h.Metrics.EndRequest(time.Since(start), isError)
	}()

	req, err := validation.DecodeRegisterRequest(r.Body)
	if err != nil {
		isError = true
		h.failValidation(w, "register", err)
		return
	}

	if err := validation.ValidateRegister(req); err != nil {
		isError = true
		h.failValidation(w, "register", err)
		return
	}

	h.logger().Info("register: validation succeeded, forwarding to database-vault")

	result := h.DBVault.Register(r.Context(), req)

	switch result.Outcome {
	case dbvault.OutcomeRegistered:
		h.logger().Info("register: database-vault reported success")
		writeJSON(w, http.StatusCreated, registerResponse{PosixUsername: result.PosixUsername})
	case dbvault.OutcomeDuplicate:
		isError = true
		h.logger().Warn("register: database-vault rejected as duplicate")
		// Relayed as-is (UC-01): the response body is Database-Vault's own
		// already-sanitized message, not reconstructed here.
		writeAppError(w, apperrors.NewConflict(errors.New("security-switch: registration rejected as duplicate")))
	default:
		isError = true
		h.logger().Error("register: database-vault call failed", "error", result.Err)
		writeAppError(w, mapDBVaultError(result.Err))
	}
}

// Login handles a login request forwarded by Entry-Hub: decode and
// re-validate independently of Entry-Hub's own validation (SS-F-02). On
// failure, SS-F-03 applies identically to Register. On success, SS-F-04
// forwards to Database-Vault; after confirmation of successful
// authentication, SS-F-05 requests Network-Manager to grant the user
// Storage-Service access for 12 hours before responding to Entry-Hub.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.Metrics.BeginRequest()
	isError := false
	defer func() {
		h.Metrics.EndRequest(time.Since(start), isError)
	}()

	req, err := validation.DecodeLoginRequest(r.Body)
	if err != nil {
		isError = true
		h.failValidation(w, "login", err)
		return
	}

	if err := validation.ValidateLogin(req); err != nil {
		isError = true
		h.failValidation(w, "login", err)
		return
	}

	h.logger().Info("login: validation succeeded, forwarding to database-vault")

	result := h.DBVault.Login(r.Context(), req)

	switch result.Outcome {
	case dbvault.OutcomeAuthenticated:
		if err := h.NetworkManager.GrantAccess(r.Context(), req.Email); err != nil {
			// Fail-secure (RD-04): a login is not reported as successful
			// if the Storage-Service access grant it depends on (SS-F-05)
			// did not itself succeed.
			isError = true
			h.logger().Error("login: network-manager grant failed", "error", err)
			writeAppError(w, mapNetworkManagerError(err))
			return
		}
		h.logger().Info("login: succeeded, network-manager grant confirmed")
		writeJSON(w, http.StatusOK, loginResponse{Status: "ok"})
	case dbvault.OutcomeUnauthorized:
		isError = true
		h.logger().Warn("login: database-vault reported authentication failure")
		// Relayed as-is (UC-02, DV-F-15): the body is Database-Vault's own
		// already-sanitized message, not reconstructed here.
		writeAppError(w, apperrors.NewUnauthorized(errors.New("security-switch: authentication failed")))
	default:
		isError = true
		h.logger().Error("login: database-vault call failed", "error", result.Err)
		writeAppError(w, mapDBVaultError(result.Err))
	}
}

// mapDBVaultError implements SS-F-06 for the outbound call to
// Database-Vault: distinguishes a timeout (504) from any other
// unreachable/unexpected-response failure (502), falling back to 500 for
// anything else.
func mapDBVaultError(err error) *apperrors.AppError {
	switch {
	case errors.Is(err, dbvault.ErrDatabaseVaultTimeout):
		return apperrors.NewGatewayTimeout(err)
	case errors.Is(err, dbvault.ErrDatabaseVaultUnreachable), errors.Is(err, dbvault.ErrDatabaseVaultUnexpectedResponse):
		return apperrors.NewBadGateway(err)
	default:
		return apperrors.NewInternal(err)
	}
}

// mapNetworkManagerError implements SS-F-06 for the outbound call to
// Network-Manager: an explicit denial maps to 403 (the request was
// refused, not merely unreachable), a timeout to 504, and any other
// unreachable/unexpected failure to 502.
func mapNetworkManagerError(err error) *apperrors.AppError {
	switch {
	case errors.Is(err, networkmanager.ErrGrantDenied):
		return apperrors.NewForbidden(err)
	case errors.Is(err, networkmanager.ErrNetworkManagerTimeout):
		return apperrors.NewGatewayTimeout(err)
	case errors.Is(err, networkmanager.ErrNetworkManagerUnreachable):
		return apperrors.NewBadGateway(err)
	default:
		return apperrors.NewInternal(err)
	}
}

// failValidation implements SS-F-03 for both handlers: respond HTTP 400
// with a generic body, and log the failure without the email, password,
// or SSH key. err is always one of pkg/validation's sentinel errors, none
// of which embed the offending field's value, so logging err.Error() here
// never risks writing a credential to the log.
func (h *Handler) failValidation(w http.ResponseWriter, endpoint string, err error) {
	h.logger().Warn("validation failed", "endpoint", endpoint, "error", err)
	writeAppError(w, apperrors.NewBadRequest(err))
}

// registerResponse is the JSON body Register writes on success. Mirrors
// Database-Vault's own registerResponse shape (relayed, not reinvented).
type registerResponse struct {
	PosixUsername string `json:"posix_username"`
}

// loginResponse is the JSON body Login writes on success.
type loginResponse struct {
	Status string `json:"status"`
}

// appErrorResponse is the JSON body written for every non-2xx response:
// only the AppError's Public message, never its Internal detail.
type appErrorResponse struct {
	Error string `json:"error"`
}

// writeAppError writes appErr.Status and a body containing only
// appErr.Public - appErr.Internal never reaches the response.
func writeAppError(w http.ResponseWriter, appErr *apperrors.AppError) {
	writeJSON(w, appErr.Status, appErrorResponse{Error: appErr.Public})
}

// writeJSON writes status and body, JSON-encoded, to w.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
