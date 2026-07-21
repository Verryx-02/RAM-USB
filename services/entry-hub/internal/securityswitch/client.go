// Package securityswitch implements Entry-Hub's outbound mTLS call to
// Security-Switch (EH-F-07): forwarding an already-validated registration
// or login request, verifying that the peer certificate's organization is
// Security-Switch and is otherwise valid, and returning Security-Switch's
// response completely unchanged - status code, headers, and body - for
// EH-F-08's handler to relay to the client byte-for-byte.
//
// This is a deliberate design difference from
// services/security-switch/internal/dbvault's own outbound client
// (SS-F-04), which decodes Database-Vault's response into a typed
// Outcome and reconstructs a new response body at its own HTTP boundary.
// EH-F-08's literal text ("must forward Security-Switch's response back
// to the user") requires passthrough, not reconstruction - Security-
// Switch's response (whatever HTTP status/body it used, including a 409
// duplicate or 401 unauthorized) is already the final, sanitized answer
// UC-01/UC-02 describe traveling back up the chain to the client
// unmodified. Only a failure of the call itself - the request never
// reaching Security-Switch, or not completing before a deadline - is a
// distinct case Entry-Hub classifies itself (EH-F-09).
//
// RegisterPath and LoginPath reproduce, verbatim, Security-Switch's own
// already-committed internal endpoint paths
// (services/security-switch/internal/httpapi/handler.go's RegisterPath/
// LoginPath doc comment) - Entry-Hub's client must match them exactly
// since Security-Switch defined that contract first.
package securityswitch

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
// services/security-switch/internal/httpapi.RegisterPath/LoginPath
// exactly.
const (
	RegisterPath = "/internal/v1/register"
	LoginPath    = "/internal/v1/login"
)

// OrganizationSecuritySwitch is the required Subject.Organization value
// on Security-Switch's server certificate (EH-F-07: "verify that the
// certificate comes from a Security-Switch"). Follows this codebase's
// established PascalCase-no-hyphen mTLS organization convention
// ("SecuritySwitch", "DatabaseVault", "StorageService", "EntryHub"),
// matching Security-Switch's own inbound check
// (services/security-switch/internal/server.AllowedClientOrganization
// is "EntryHub" - the symmetric outbound-facing constant here).
const OrganizationSecuritySwitch = "SecuritySwitch"

// Result is what Register/Login return: either Security-Switch's own
// response, completely unchanged (StatusCode, ContentType, Body all
// non-zero, Err nil), or a call failure (Err non-nil, everything else
// zero) - never both.
type Result struct {
	// StatusCode is Security-Switch's own HTTP response status, relayed
	// unchanged (EH-F-08).
	StatusCode int
	// ContentType is Security-Switch's own Content-Type response header,
	// relayed unchanged. Empty only if Security-Switch's response did not
	// set one.
	ContentType string
	// Body is Security-Switch's own raw response body bytes, relayed
	// unchanged (EH-F-08) - never re-encoded or re-parsed by this
	// package.
	Body []byte
	// Err is nil when Security-Switch's response was received in full;
	// it is non-nil only when the call itself did not complete. Never
	// carries any per-user content (email, password, SSH key).
	Err error
}

// Sentinel errors distinguishing why a call did not complete. None of
// these embed request content; a caller may log them freely (EH-F-09).
var (
	// ErrSecuritySwitchUnreachable means the HTTP/mTLS call itself did
	// not complete (connection refused, TLS/organization rejection, a
	// response body that could not be fully read, ...).
	ErrSecuritySwitchUnreachable = errors.New("securityswitch: unreachable")
	// ErrSecuritySwitchTimeout means the call did not complete before
	// its context deadline elapsed.
	ErrSecuritySwitchTimeout = errors.New("securityswitch: timed out waiting for response")
)

// Register forwards req to Security-Switch's RegisterPath over client
// (expected to already be configured with mtls.ClientConfig verifying
// OrganizationSecuritySwitch) and returns its response unchanged
// (EH-F-07, EH-F-08).
func Register(ctx context.Context, client *http.Client, baseURL string, req validation.RegisterRequest) Result {
	return forward(ctx, client, baseURL+RegisterPath, req)
}

// Login forwards req to Security-Switch's LoginPath over client and
// returns its response unchanged (EH-F-07, EH-F-08).
func Login(ctx context.Context, client *http.Client, baseURL string, req validation.LoginRequest) Result {
	return forward(ctx, client, baseURL+LoginPath, req)
}

// forward marshals body as JSON, POSTs it to url over client, and returns
// the peer's response completely unchanged. Any failure short of
// receiving a complete HTTP response is reported as
// ErrSecuritySwitchUnreachable, or ErrSecuritySwitchTimeout if the
// failure was a context deadline.
func forward(ctx context.Context, client *http.Client, url string, body any) Result {
	encoded, err := json.Marshal(body)
	if err != nil {
		return Result{Err: fmt.Errorf("securityswitch: encode request: %w", err)}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return Result{Err: fmt.Errorf("securityswitch: build request: %w", err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Result{Err: fmt.Errorf("%w: %w", ErrSecuritySwitchTimeout, err)}
		}
		return Result{Err: fmt.Errorf("%w: %w", ErrSecuritySwitchUnreachable, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{Err: fmt.Errorf("%w: read response: %w", ErrSecuritySwitchUnreachable, err)}
	}

	return Result{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        respBody,
	}
}
