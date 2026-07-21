// Package dbvault implements Security-Switch's outbound mTLS call to
// Database-Vault (SS-F-04): forwarding an already-locally-revalidated
// registration or login request, verifying that the peer certificate's
// organization is Database-Vault and is otherwise valid, and translating
// Database-Vault's response into an Outcome the caller (internal/httpapi)
// can switch on without inspecting Database-Vault's raw response body
// itself.
//
// Database-Vault's login response never needs to carry a user identifier:
// per UC-02 and SRS 2.6, Security-Switch already has the user's email from
// the login request it is forwarding, and SS-F-05's Network-Manager grant
// targets that same email's already-existing mesh node (joined once, at
// registration, via a pre-auth key), not a value echoed back through this
// response chain.
//
// RegisterPath and LoginPath reproduce, verbatim, the invented paths
// Database-Vault's own httpapi package documents
// (services/database-vault/internal/httpapi/handler.go's RegisterPath/
// LoginPath doc comment) - Security-Switch's client must match them
// exactly since Database-Vault defined that contract first. The request
// body sent is validation.RegisterRequest/LoginRequest marshaled directly:
// its json tags (email, password, ssh_public_key) already match what
// Database-Vault's own DecodeRegisterRequest/DecodeLoginRequest expect, so
// no separate wire-format struct is needed on the request side.
package dbvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

// RegisterPath and LoginPath must match
// services/database-vault/internal/httpapi.RegisterPath/LoginPath exactly.
const (
	RegisterPath = "/internal/v1/register"
	LoginPath    = "/internal/v1/login"
)

// OrganizationDatabaseVault is the required Subject.Organization value on
// Database-Vault's server certificate (SS-F-04: "the certificate comes
// from a Database-Vault"). No literal `organization="..."` value is given
// anywhere in the SRS for this direction (only DV-F-01's inbound check,
// organization="SecuritySwitch", is a literal SRS value) - this string is
// this session's judgment call, following the codebase's established
// PascalCase-no-hyphen mTLS organization convention ("SecuritySwitch",
// "StorageService", "EntryHub").
const OrganizationDatabaseVault = "DatabaseVault"

// registerResponse mirrors Database-Vault's own registerResponse exactly
// (services/database-vault/internal/httpapi/handler.go).
type registerResponse struct {
	PosixUsername string `json:"posix_username"`
}

// loginResponse mirrors Database-Vault's own loginResponse exactly
// (services/database-vault/internal/httpapi/handler.go): only a Status
// field. Database-Vault never needs to echo back a user identifier -
// Security-Switch already has the user's email from the login request it
// is forwarding (decoded via validation.DecodeLoginRequest before this
// client is ever called), and SS-F-05's Network-Manager grant identifies
// the user's already-existing mesh node (joined once, at registration, via
// UC-01 step 8's pre-auth key) by that same email, not by anything
// Database-Vault's response carries.
type loginResponse struct {
	Status string `json:"status"`
}

// appErrorResponse mirrors Database-Vault's own appErrorResponse: only the
// AppError's Public message, never any internal detail.
type appErrorResponse struct {
	Error string `json:"error"`
}

// Outcome enumerates how Database-Vault responded to a forwarded request.
type Outcome int

const (
	// OutcomeUnknown means the call either did not complete (see Result.Err,
	// wrapping ErrDatabaseVaultUnreachable or ErrDatabaseVaultTimeout) or
	// Database-Vault responded with a status this client does not
	// recognize as one of the outcomes below (Result.Err wraps
	// ErrDatabaseVaultUnexpectedResponse). Fail-secure (RD-04): treated as
	// a failure by every caller, never as success.
	OutcomeUnknown Outcome = iota
	// OutcomeRegistered means Database-Vault responded 201 Created.
	OutcomeRegistered
	// OutcomeDuplicate means Database-Vault responded 409 Conflict
	// (DV-F-12) - relayed to Entry-Hub as-is, per UC-01's sequence diagram.
	OutcomeDuplicate
	// OutcomeAuthenticated means Database-Vault responded 200 OK to a
	// login request.
	OutcomeAuthenticated
	// OutcomeUnauthorized means Database-Vault responded 401 Unauthorized
	// (DV-F-15) - relayed to Entry-Hub as-is, per UC-02's sequence diagram.
	OutcomeUnauthorized
)

// Result is what Register/Login return: the Outcome plus whatever
// Outcome-specific data Database-Vault's response carried.
type Result struct {
	Outcome Outcome
	// PosixUsername is set only when Outcome is OutcomeRegistered.
	PosixUsername string
	// Err is nil for every recognized Outcome above OutcomeUnknown; it is
	// non-nil only when Outcome is OutcomeUnknown, and never carries any
	// per-user content (email, password, SSH key) - see the sentinel
	// errors below.
	Err error
}

// Sentinel errors distinguishing why a call resulted in OutcomeUnknown.
// None of these embed request content; a caller may log them freely.
var (
	// ErrDatabaseVaultUnreachable means the HTTP/mTLS call itself did not
	// complete (connection refused, TLS/organization rejection, a
	// malformed response body, ...).
	ErrDatabaseVaultUnreachable = errors.New("dbvault: unreachable")
	// ErrDatabaseVaultTimeout means the call did not complete before its
	// context deadline elapsed.
	ErrDatabaseVaultTimeout = errors.New("dbvault: timed out waiting for response")
	// ErrDatabaseVaultUnexpectedResponse means Database-Vault responded,
	// but with a status code or body this client does not recognize as
	// one of the outcomes above.
	ErrDatabaseVaultUnexpectedResponse = errors.New("dbvault: unexpected response")
)

// Register forwards req to Database-Vault's RegisterPath over client
// (expected to already be configured with mtls.ClientConfig verifying
// OrganizationDatabaseVault) and waits for its response (SS-F-04).
func Register(ctx context.Context, client *http.Client, baseURL string, req validation.RegisterRequest) Result {
	respBody, status, err := forward(ctx, client, baseURL+RegisterPath, req)
	if err != nil {
		return Result{Outcome: OutcomeUnknown, Err: err}
	}

	switch status {
	case http.StatusCreated:
		var parsed registerResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return Result{Outcome: OutcomeUnknown, Err: fmt.Errorf("%w: malformed success body: %w", ErrDatabaseVaultUnexpectedResponse, err)}
		}
		return Result{Outcome: OutcomeRegistered, PosixUsername: parsed.PosixUsername}
	case http.StatusConflict:
		return Result{Outcome: OutcomeDuplicate}
	default:
		return Result{Outcome: OutcomeUnknown, Err: fmt.Errorf("%w: status %d", ErrDatabaseVaultUnexpectedResponse, status)}
	}
}

// Login forwards req to Database-Vault's LoginPath over client and waits
// for its response (SS-F-04).
func Login(ctx context.Context, client *http.Client, baseURL string, req validation.LoginRequest) Result {
	respBody, status, err := forward(ctx, client, baseURL+LoginPath, req)
	if err != nil {
		return Result{Outcome: OutcomeUnknown, Err: err}
	}

	switch status {
	case http.StatusOK:
		var parsed loginResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return Result{Outcome: OutcomeUnknown, Err: fmt.Errorf("%w: malformed success body: %w", ErrDatabaseVaultUnexpectedResponse, err)}
		}
		return Result{Outcome: OutcomeAuthenticated}
	case http.StatusUnauthorized:
		return Result{Outcome: OutcomeUnauthorized}
	default:
		return Result{Outcome: OutcomeUnknown, Err: fmt.Errorf("%w: status %d", ErrDatabaseVaultUnexpectedResponse, status)}
	}
}

// forward marshals body as JSON, POSTs it to url over client, and returns
// the raw response bytes and status code. Any failure short of receiving a
// complete HTTP response is reported as ErrDatabaseVaultUnreachable, or
// ErrDatabaseVaultTimeout if the failure was a context deadline.
func forward(ctx context.Context, client *http.Client, url string, body any) ([]byte, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("dbvault: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, fmt.Errorf("dbvault: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, fmt.Errorf("%w: %w", ErrDatabaseVaultTimeout, err)
		}
		return nil, 0, fmt.Errorf("%w: %w", ErrDatabaseVaultUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read response: %w", ErrDatabaseVaultUnreachable, err)
	}

	return respBody, resp.StatusCode, nil
}
