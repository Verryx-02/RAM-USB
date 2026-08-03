// Package httpapi wires every already-implemented Database-Vault building
// block — pkg/validation (DV-F-02), internal/hashing (DV-F-03),
// internal/encryption (DV-F-04), internal/password (DV-F-07),
// internal/registration (DV-F-09..DV-F-12), and internal/login
// (DV-F-13..DV-F-15) — into the two HTTP handlers Security-Switch calls
// over the mTLS listener DV-F-01/internal/server configures.
//
// DV-F-20 is enforced at the top of both handlers: a decode or validation
// failure responds HTTP 400 with a generic body, logs the failure without
// any user-identifying value, and returns immediately — registration.
// Register/login.Login are never called on that path.
//
// No literal path is specified anywhere in the SRS or design docs for
// Database-Vault's own internal endpoints (only Entry-Hub's
// public-facing /api/register and /api/login are named). RegisterPath and
// LoginPath below are this session's invented judgment call, the same
// pattern as DV-F-09's invented Storage-Service HTTP contract — revisit if
// Security-Switch's eventual client (SS-F-04) fixes different values.
package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/logging"
	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/hashing"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/login"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/password"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/registration"
)

// RegisterPath and LoginPath are Database-Vault's own internal endpoint
// paths. See the package doc comment: these are invented, not sourced
// from the SRS or a design doc.
const (
	RegisterPath = "/internal/v1/register"
	LoginPath    = "/internal/v1/login"
)

// Handler ties the registration and login orchestration packages to
// net/http, providing DV-F-02's re-validation and DV-F-20's
// validation-failure handling at the boundary in front of both.
type Handler struct {
	// Store persists and deletes user records (DV-F-08, DV-F-10),
	// typically a registration.StorageAdapter wrapping a storage.Beginner.
	Store registration.Storage

	// POSIXProvisioner asks Storage-Service to create the POSIX user
	// (DV-F-09), typically a registration.POSIXAdapter wrapping an
	// *http.Client configured with pkg/mtls.ClientConfig.
	POSIXProvisioner registration.POSIXProvisioner

	// LoginStore retrieves the stored password hash by email hash
	// (DV-F-13), typically a login.StorageAdapter wrapping a
	// storage.Querier.
	LoginStore login.Storage

	// MasterKey is the already-loaded, already-length-validated 32-byte
	// key encryption.EncryptEmail uses (DV-F-04, DV-F-05).
	MasterKey []byte

	// Pepper is the already-loaded shared secret password.HashPassword/
	// VerifyPassword use (DV-F-06).
	Pepper []byte

	// Metrics accumulates request/error/response-time counts feeding
	// DV-F-16/DV-F-17's periodic publish. Must not be nil.
	Metrics *metrics.RequestCounters

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used. Tests inject a logger writing to a
	// buffer to assert DV-F-20's "no user-identifying value in the log"
	// requirement.
	Logger *slog.Logger
}

// logger returns h.Logger, or slog.Default() if unset.
func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// Register handles a registration request: decode (DV-F-02), re-validate
// (DV-F-02), and on success compute the email hash (DV-F-03), the
// encrypted email (DV-F-04), and the password hash (DV-F-07), then hand
// off to registration.Register (DV-F-09..DV-F-12). On a decode or
// validation failure, DV-F-20 applies: HTTP 400, a generic body, a log
// line without the email or password, and no call to Register/Store/
// POSIXProvisioner at all.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	isError := false
	defer h.Metrics.Track(&isError)()

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

	emailHash := hashing.HashEmail(logging.Redacted(req.Email))

	emailEncrypted, err := encryption.EncryptEmail(h.MasterKey, logging.Redacted(req.Email))
	if err != nil {
		isError = true
		h.logger().Error("register: encrypt email failed", "error", err)
		apperrors.WriteAppError(w, apperrors.NewInternal(err))
		return
	}

	salt, err := password.GenerateSalt()
	if err != nil {
		isError = true
		h.logger().Error("register: generate salt failed", "error", err)
		apperrors.WriteAppError(w, apperrors.NewInternal(err))
		return
	}

	passwordHash, err := password.HashPassword([]byte(req.Password), salt, h.Pepper)
	if err != nil {
		isError = true
		h.logger().Error("register: hash password failed", "error", err)
		apperrors.WriteAppError(w, apperrors.NewInternal(err))
		return
	}

	result := registration.Register(r.Context(), h.Store, h.POSIXProvisioner, registration.Input{
		EmailHash:      emailHash,
		EmailEncrypted: emailEncrypted,
		PasswordHash:   passwordHash,
		SSHPublicKey:   req.SSHPublicKey,
	})

	switch result.Outcome {
	case registration.OutcomeRegistered:
		h.logger().Info("register: succeeded")
		apperrors.WriteJSON(w, http.StatusCreated, registerResponse{PosixUsername: result.PosixUsername})
	case registration.OutcomeDuplicate:
		isError = true
		h.logger().Warn("register: rejected as duplicate", "error", result.Err)
		apperrors.WriteAppError(w, apperrors.NewConflict(result.Err))
	default:
		isError = true
		h.logger().Error("register: failed", "error", result.Err)
		apperrors.WriteAppError(w, apperrors.NewInternal(result.Err))
	}
}

// Login handles a login request: decode (DV-F-02), re-validate (DV-F-02),
// and on success hand off to login.Login (DV-F-13..DV-F-15). On a decode
// or validation failure, DV-F-20 applies identically to Register.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	isError := false
	defer h.Metrics.Track(&isError)()

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

	result := login.Login(r.Context(), h.LoginStore, h.Pepper, login.Input{
		Email:    logging.Redacted(req.Email),
		Password: []byte(req.Password),
	})

	switch result.Outcome {
	case login.OutcomeSuccess:
		h.logger().Info("login: succeeded")
		apperrors.WriteJSON(w, http.StatusOK, loginResponse{Status: "ok"})
	default:
		isError = true
		// DV-F-15: result.Err is already one of the three fixed sentinels
		// (login.ErrAuthenticationFailed, login.ErrPasswordVerificationFailed,
		// login.ErrLookupFailed) carrying no per-record content — safe to log
		// as-is. The latter two are internal faults (corrupt stored hash,
		// database unreachable) rather than a user's bad credentials, so
		// they are logged at Error level: a database outage must not look
		// like a wave of failed logins in the operator's dashboard.
		level := slog.LevelWarn
		if errors.Is(result.Err, login.ErrPasswordVerificationFailed) || errors.Is(result.Err, login.ErrLookupFailed) {
			level = slog.LevelError
		}
		h.logger().Log(r.Context(), level, "login: failed", "error", result.Err)
		apperrors.WriteAppError(w, apperrors.NewUnauthorized(result.Err))
	}
}

// failValidation implements DV-F-20 for both handlers: respond HTTP 400
// with a generic body, and log the failure without the email, password,
// or SSH key. err is always one of pkg/validation's sentinel errors
// (ErrEmailInvalid, ErrPasswordTooShort, ...), none of which embed the
// offending field's value, so logging err.Error() here never risks
// writing a credential to the log.
func (h *Handler) failValidation(w http.ResponseWriter, endpoint string, err error) {
	failBadRequest(w, h.logger(), err, "validation failed", "endpoint", endpoint, "error", err)
}

// failBadRequest is the package-level building block DV-F-20's
// failValidation above and PublicKeyHandler.PublicKey's malformed-username
// rejection both call: log msg/args via logger (callers pass only sanitized/
// generic fields, never the offending raw value) and respond HTTP 400 with
// apperrors.NewBadRequest(err)'s generic body. Kept as a free function
// rather than a Handler method so PublicKeyHandler — deliberately its own
// type, see pubkey_handler.go's package doc comment for why it doesn't
// share Handler's dependencies — can reuse it without gaining any of
// Handler's fields.
func failBadRequest(w http.ResponseWriter, logger *slog.Logger, err error, msg string, args ...any) {
	logger.Warn(msg, args...)
	apperrors.WriteAppError(w, apperrors.NewBadRequest(err))
}

// registerResponse is the JSON body Register writes on success. No SRS or
// design doc specifies this shape; it is this session's judgment call,
// same as RegisterPath/LoginPath.
type registerResponse struct {
	PosixUsername string `json:"posix_username"`
}

// loginResponse is the JSON body Login writes on success.
type loginResponse struct {
	Status string `json:"status"`
}
