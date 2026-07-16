// Package httpapi implements Entry-Hub's public-facing HTTP handlers:
// the health-check endpoint (EH-F-01), registration (EH-F-02/EH-F-04/
// EH-F-06/EH-F-07/EH-F-08/EH-F-09), and login (EH-F-03/EH-F-05/EH-F-06/
// EH-F-07/EH-F-08/EH-F-09).
//
// Decoding and field-level validation reuse pkg/validation
// (DecodeRegisterRequest/DecodeLoginRequest, ValidateRegister/
// ValidateLogin) exactly - EH-F-04/EH-F-05's rule list (payload size,
// unknown fields, RFC 5322 email, 8-128 char password with 3-of-4
// complexity, well-formed SSH key) is the identical shared logic
// Security-Switch's own SS-F-02 re-validation and Database-Vault's
// DV-F-02 re-validation already call - this is Entry-Hub's own,
// independent call to the same shared rules (RNF-SEC-02/RNF-SEC-03), not
// a separate implementation of them.
//
// EH-F-06 is enforced at the top of both Register and Login: a decode or
// validation failure responds HTTP 400 with a generic body, logs the
// failure without any user-identifying value, and returns immediately -
// no downstream call is made on that path. Forwarding a validated
// request to Security-Switch (EH-F-07/EH-F-08/EH-F-09) is implemented in
// forward.go, alongside this file.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

// HealthPath, RegisterPath, and LoginPath are Entry-Hub's public-facing
// endpoint paths, literally specified by EH-F-01/EH-F-02/EH-F-03. Each is
// a bare URL path (usable directly as an httptest.NewRequest target),
// not a Go 1.22+ enhanced-ServeMux "METHOD pattern" string - main.go
// combines a path with its required POST method
// (net/http.ServeMux.HandleFunc("POST "+httpapi.RegisterPath, ...)) at
// registration time, keeping this constant reusable as a plain path in
// tests too.
const (
	HealthPath   = "/api/health"
	RegisterPath = "/api/register"
	LoginPath    = "/api/login"
)

// Handler ties Entry-Hub's public endpoints together: health (EH-F-01),
// registration re-validation and forwarding (EH-F-02/04/06/07/08/09), and
// login re-validation and forwarding (EH-F-03/05/06/07/08/09).
type Handler struct {
	// SecuritySwitch forwards an already-validated request to
	// Security-Switch over mTLS (EH-F-07), typically a
	// SecuritySwitchAdapter wrapping an *http.Client configured with
	// pkg/mtls.ClientConfig verifying
	// securityswitch.OrganizationSecuritySwitch. Must not be nil for
	// Register/Login - only Health has no downstream dependency.
	SecuritySwitch SecuritySwitchClient

	// Metrics accumulates request/error/response-time counts feeding
	// EH-F-10/EH-F-11's periodic publish. Must not be nil for
	// Register/Login.
	Metrics *Counters

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used. Tests inject a logger writing to a
	// buffer to assert EH-F-06's "no user-identifying value in the log"
	// requirement, same pattern as Security-Switch's SS-F-03 handler
	// test and Database-Vault's DV-F-20 handler test.
	Logger *slog.Logger
}

// logger returns h.Logger, or slog.Default() if unset.
func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// healthResponse is the JSON body Health writes on success.
type healthResponse struct {
	Status string `json:"status"`
}

// Health responds 200 OK to any request reaching it - EH-F-01 requires
// only that the endpoint be reachable over Entry-Hub's public HTTPS
// listener, with no further condition.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

// Register handles a registration request from a client (CL-F-02):
// decode and validate (EH-F-02, EH-F-04). On failure, EH-F-06 applies:
// HTTP 400, a generic body, a log line without the email/password/SSH
// key, and no call to Security-Switch at all. On success, EH-F-07
// applies: log the outcome without identifying the user, then forward to
// Security-Switch and relay its response unchanged (EH-F-08/EH-F-09) -
// see forward.go.
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

	h.logger().Info("register: validation succeeded, forwarding to security-switch")

	h.forwardRegister(w, r, req, &isError)
}

// Login handles a login request from a client (CL-F-03): decode and
// validate (EH-F-03, EH-F-05). On failure, EH-F-06 applies identically to
// Register. On success, EH-F-07 forwards to Security-Switch and relays
// its response unchanged (EH-F-08/EH-F-09) - see forward.go.
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

	h.logger().Info("login: validation succeeded, forwarding to security-switch")

	h.forwardLogin(w, r, req, &isError)
}

// failValidation implements EH-F-06 for both handlers: respond HTTP 400
// with a generic body, and log the failure without the email, password,
// or SSH key. err is always one of pkg/validation's sentinel errors, none
// of which embed the offending field's value, so logging err.Error() here
// never risks writing a credential to the log.
func (h *Handler) failValidation(w http.ResponseWriter, endpoint string, err error) {
	h.logger().Warn("validation failed", "endpoint", endpoint, "error", err)
	writeAppError(w, apperrors.NewBadRequest(err))
}

// appErrorResponse is the JSON body written when Entry-Hub constructs its
// own error response (EH-F-06's validation-failure body, and EH-F-09's
// mapped downstream-call-failure body) - only the AppError's Public
// message, never its Internal detail. A response Security-Switch itself
// produced is instead relayed byte-for-byte via forward.go's
// writeForwardedResponse, not re-encoded through this type.
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
