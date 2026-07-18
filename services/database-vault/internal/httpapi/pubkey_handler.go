// This file adds ST-F-11's public-key lookup endpoint alongside handler.go's
// Register/Login handlers, as a separate PublicKeyHandler type rather than
// new methods on Handler: it is reached over a completely different mTLS
// listener (internal/server's NewPublicKeyTLSConfig, organization=
// "StorageService", not "SecuritySwitch"), by a different caller, for a
// different purpose, and shares none of Register/Login's dependencies
// (registration.Storage, registration.POSIXProvisioner, login.Storage,
// MasterKey, Pepper). Bolting a third method onto the existing Handler
// struct would force every Register/Login caller (cmd/database-vault/
// main.go, and every existing test) to also thread through a
// PublicKeyStore dependency it has no use for.
//
// Endpoint contract, invented and documented here since no SRS or design
// doc specifies one (Storage-Service's own AuthorizedKeysCommand side,
// ST-F-11's other half, does not exist yet either — both sides of this
// contract are being defined together conceptually, only this side is
// built now): GET /internal/v1/public-key/{posix_username} returns
// {"ssh_public_key": "..."} with HTTP 200 on a match, or a generic AppError
// body with HTTP 404 if posixUsername matches no user, or HTTP 400 if
// posixUsername fails this handler's own structural re-validation.
//
// No-detail-leak decision, deliberately different from DV-F-15/DV-F-20's
// "never distinguish why" pattern: DV-F-15 forbids telling an external,
// potentially adversarial caller whether an email exists (that
// distinguishability is itself the exploitable signal, enabling
// account-enumeration attacks against arbitrary end users). This endpoint
// has no external caller at all — only Storage-Service, already
// authenticated via its own dedicated mTLS listener, ever reaches it — and
// "no such posix_username" is not a per-end-user secret to protect from a
// service that already knows the very identifier it is asking about
// (sshd handed it that username itself, invoking AuthorizedKeysCommand
// with it as an argument). A distinct HTTP 404 is therefore both safe and
// more useful than a generic catch-all here: Storage-Service's own
// AuthorizedKeysCommand implementation (not yet built) needs to tell "this
// account genuinely has no key on record, deny the SSH connection" apart
// from "the lookup itself failed, treat as fail-secure/deny too" for its
// own logging, even though both ultimately result in denying the
// connection either way (RD-04).
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// PublicKeyPath is the pattern this handler is registered under on its own
// dedicated mux/listener (see internal/server.NewPublicKeyTLSConfig's doc
// comment for why this runs on a separate listener from RegisterPath/
// LoginPath, not merely a separate path on the same one). Unlike
// RegisterPath/LoginPath, this pattern includes the "GET " method prefix
// supported by net/http.ServeMux's enhanced routing (Go 1.22+) plus a
// {posix_username} path wildcard, read via (*http.Request).PathValue —
// there is no existing RegisterPath/LoginPath-style convention to match
// here since this endpoint's shape (a path parameter, not a JSON body) is
// new.
const PublicKeyPath = "GET /internal/v1/public-key/{posix_username}"

// posixUsernamePattern re-validates the path parameter against DV-F-09's
// exact "user<xxxxxx>" format (six lowercase base-36 characters) before
// ever querying the database — RNF-SEC-02/03's zero-trust principle
// applied here: Storage-Service is the only caller this listener accepts,
// but this handler does not assume every request it sends is well-formed.
// Mirrors storage-service/internal/httpapi's own re-validation of the same
// format on its receiving side of DV-F-09/ST-F-06.
var posixUsernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// errMalformedPosixUsername is logged (never with the offending value
// attached, see logger() calls below) when the path parameter fails
// posixUsernamePattern.
var errMalformedPosixUsername = errors.New("public-key: malformed posix username")

// PublicKeyStore is the minimal interface PublicKeyHandler needs: one
// lookup by posix_username. Depending on this narrow interface, instead of
// storage.Querier or *pgxpool.Pool directly, lets unit tests substitute a
// hand-written fake per CONTRIBUTING.md §7.5 — same "narrow interface +
// adapter over a free function" shape as registration.Storage/
// login.Storage's own adapters.
type PublicKeyStore interface {
	GetSSHPublicKey(ctx context.Context, posixUsername string) (string, error)
}

// PublicKeyStoreAdapter adapts storage.GetSSHPublicKeyByPosixUsername (a
// free function taking a storage.Querier) to PublicKeyStore.
type PublicKeyStoreAdapter struct {
	DB storage.Querier
}

// GetSSHPublicKey implements PublicKeyStore.
func (a PublicKeyStoreAdapter) GetSSHPublicKey(ctx context.Context, posixUsername string) (string, error) {
	return storage.GetSSHPublicKeyByPosixUsername(ctx, a.DB, posixUsername)
}

// PublicKeyHandler implements ST-F-11's receiving side: Storage-Service's
// (not yet built) AuthorizedKeysCommand calls this over the mTLS listener
// internal/server.NewPublicKeyTLSConfig configures.
type PublicKeyHandler struct {
	// Store retrieves the stored ssh_public_key by posix_username,
	// typically a PublicKeyStoreAdapter wrapping a storage.Querier.
	Store PublicKeyStore

	// Metrics accumulates request/error/response-time counts feeding
	// DV-F-16/DV-F-17's periodic publish, shared with Handler's own
	// Register/Login traffic — both count toward the same one
	// service-wide metrics snapshot, there is no separate "public-key"
	// metric.
	Metrics *Counters

	// Logger receives every structured log line this handler writes. If
	// nil, slog.Default() is used, same fallback as Handler.Logger.
	Logger *slog.Logger
}

// logger returns h.Logger, or slog.Default() if unset.
func (h *PublicKeyHandler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// PublicKey handles a public-key lookup request: re-validate the path
// parameter's structural shape, then look it up via Store. See the package
// doc comment for why a distinct HTTP 404 (posixUsername well-formed but no
// matching user) is safe to return here, unlike DV-F-15's login lookup.
func (h *PublicKeyHandler) PublicKey(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.Metrics.BeginRequest()
	isError := false
	defer func() {
		h.Metrics.EndRequest(time.Since(start), isError)
	}()

	posixUsername := r.PathValue("posix_username")
	if !posixUsernamePattern.MatchString(posixUsername) {
		isError = true
		// Never log posixUsername itself here: an unvalidated path value
		// is untrusted input, and this codebase's convention (DV-F-20) is
		// to log a validation failure's cause, never the offending raw
		// value.
		h.logger().Warn("public-key: rejected malformed posix username")
		writeAppError(w, apperrors.NewBadRequest(errMalformedPosixUsername))
		return
	}

	sshPublicKey, err := h.Store.GetSSHPublicKey(r.Context(), posixUsername)
	if err != nil {
		isError = true
		if errors.Is(err, storage.ErrPosixUsernameNotFound) {
			h.logger().Info("public-key: not found")
			writeAppError(w, apperrors.NewNotFound(err))
			return
		}
		h.logger().Error("public-key: lookup failed", "error", err)
		writeAppError(w, apperrors.NewInternal(err))
		return
	}

	h.logger().Info("public-key: succeeded")
	writeJSON(w, http.StatusOK, publicKeyResponse{SSHPublicKey: sshPublicKey})
}

// publicKeyResponse is the JSON body PublicKey writes on success. No SRS or
// design doc specifies this shape; it is this session's judgment call, same
// as registerResponse/loginResponse in handler.go.
type publicKeyResponse struct {
	SSHPublicKey string `json:"ssh_public_key"`
}
