// Package entryhub implements the Client's HTTP calls to Entry-Hub:
// registration (CL-F-02) and login (CL-F-03), both preceded by local
// pre-validation (CL-F-09) using the exact same rules Entry-Hub itself
// enforces (EH-F-04/EH-F-05), and both mapping Entry-Hub's HTTP error
// codes to sanitized, user-facing messages (CL-F-08) rather than ever
// surfacing a raw response body to the terminal.
//
// This client speaks plain HTTPS, not mTLS: Entry-Hub's public
// registration/login endpoints are the one boundary in the whole system a
// client does not present a certificate to (every other component-to-
// component hop uses mTLS, but a not-yet-registered user has no client
// certificate to present in the first place).
package entryhub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

// RegisterPath and LoginPath are Entry-Hub's public endpoint paths,
// literally specified by CL-F-02/CL-F-03/EH-F-02/EH-F-03. Reproduced here
// (not imported from services/entry-hub/internal/httpapi, which Go's
// internal-package visibility rule makes unreachable from user-client)
// exactly as UC-01/UC-02 name them.
const (
	RegisterPath = "/api/register"
	LoginPath    = "/api/login"
)

// defaultTimeout bounds how long a single Register/Login HTTP call may
// take before this client reports it as unreachable. The SRS specifies no
// client-side timeout value; 30s is this session's judgment call, generous
// enough for a chain of several downstream mTLS hops (UC-01/UC-02) to
// complete under normal conditions.
const defaultTimeout = 30 * time.Second

// ErrLocalValidationFailed wraps whatever pkg/validation sentinel error
// caused a local pre-validation failure (CL-F-09). Callers use
// errors.Unwrap or errors.Is against the specific pkg/validation sentinel
// for detail; the sentinel itself never embeds the offending field's
// value, so it is always safe to print directly.
var ErrLocalValidationFailed = errors.New("entryhub: request failed local validation")

// ErrUnreachable means the HTTP call to Entry-Hub did not complete at all
// (DNS failure, connection refused, TLS failure, timeout) - distinct from
// Entry-Hub returning one of CL-F-08's recognized error status codes.
var ErrUnreachable = errors.New("entryhub: could not reach entry-hub")

// Client sends registration and login requests to Entry-Hub.
type Client struct {
	// HTTPClient performs the actual HTTP call. If nil, New's default
	// (a plain *http.Client with defaultTimeout) is used.
	HTTPClient *http.Client

	// BaseURL is Entry-Hub's base URL (e.g. "https://entry-hub.mesh"),
	// without a trailing slash.
	BaseURL string
}

// New returns a Client targeting baseURL with a default-configured
// *http.Client (plain TLS, defaultTimeout).
func New(baseURL string) *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: defaultTimeout},
		BaseURL:    baseURL,
	}
}

// httpClient returns c.HTTPClient, or a default-timeout client if unset.
func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: defaultTimeout}
}

// RegisterResult holds Entry-Hub's response to a successful registration
// (UC-01 step 8).
type RegisterResult struct {
	// PosixUsername is the POSIX account Storage-Service created for this
	// user (relayed unchanged from Database-Vault through Security-Switch
	// and Entry-Hub).
	PosixUsername string

	// PreauthKey is the Tailscale pre-auth key CL-F-04 needs to join the
	// mesh, minted by Network-Manager (NM-F-08) on request from
	// Security-Switch (SS-F-09) after Database-Vault confirms
	// registration, and relayed unchanged through Entry-Hub (UC-01 step
	// 7-8). Callers (CL-F-04) should still handle an empty value
	// gracefully (e.g. Security-Switch's SS-F-09 call to Network-Manager
	// failed server-side) rather than treat it as a hard error.
	PreauthKey string
}

// registerResponse is the JSON body this client expects from Entry-Hub on
// a successful registration. PosixUsername matches Security-Switch's own
// registerResponse (relayed unchanged); PreauthKey matches Network-Manager's
// own meshUserResponse.PreAuthKey field name (pre_auth_key), relayed
// unchanged through Security-Switch and Entry-Hub.
type registerResponse struct {
	PosixUsername string `json:"posix_username"`
	PreauthKey    string `json:"pre_auth_key"`
}

// appErrorResponse mirrors every service's own appErrorResponse shape
// (services/entry-hub/internal/httpapi/handler.go and its downstream
// peers): only a sanitized "error" message, never internal detail.
type appErrorResponse struct {
	Error string `json:"error"`
}

// Register implements CL-F-02: locally pre-validate req (CL-F-09) using
// the exact rules Entry-Hub enforces (EH-F-04), and only if that passes,
// send POST /api/register. On a local validation failure, no request is
// sent at all.
func (c *Client) Register(ctx context.Context, req validation.RegisterRequest) (RegisterResult, error) {
	if err := validation.ValidateRegister(req); err != nil {
		return RegisterResult{}, fmt.Errorf("%w: %v", ErrLocalValidationFailed, err)
	}

	body, status, err := c.post(ctx, RegisterPath, req)
	if err != nil {
		return RegisterResult{}, err
	}

	if status != http.StatusCreated {
		return RegisterResult{}, mapStatusError(status, body)
	}

	var parsed registerResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return RegisterResult{}, apperrors.NewInternal(fmt.Errorf("entryhub: malformed success body: %w", err))
	}
	return RegisterResult(parsed), nil
}

// Login implements CL-F-03: locally pre-validate req (CL-F-09) using the
// exact rules Entry-Hub enforces (EH-F-05), and only if that passes, send
// POST /api/login. On a local validation failure, no request is sent at
// all.
func (c *Client) Login(ctx context.Context, req validation.LoginRequest) error {
	if err := validation.ValidateLogin(req); err != nil {
		return fmt.Errorf("%w: %v", ErrLocalValidationFailed, err)
	}

	body, status, err := c.post(ctx, LoginPath, req)
	if err != nil {
		return err
	}

	if status != http.StatusOK {
		return mapStatusError(status, body)
	}
	return nil
}

// post marshals body as JSON, POSTs it to c.BaseURL+path, and returns the
// raw response bytes and status code. Any failure short of receiving a
// complete HTTP response is reported as ErrUnreachable.
func (c *Client) post(ctx context.Context, path string, body any) ([]byte, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("entryhub: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, fmt.Errorf("entryhub: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read response: %v", ErrUnreachable, err)
	}

	return respBody, resp.StatusCode, nil
}

// mapStatusError implements CL-F-08: maps one of Entry-Hub's documented
// error status codes (400/401/403/500/502/503/504) to the matching
// pkg/errors.AppError, whose Public field is always the fixed, sanitized
// message for that status - never Entry-Hub's own raw response body,
// which is only recorded in the returned AppError's Internal field for
// local debugging, never printed to the end user.
func mapStatusError(status int, body []byte) *apperrors.AppError {
	var parsed appErrorResponse
	_ = json.Unmarshal(body, &parsed)
	internal := fmt.Errorf("entryhub: status %d: %s", status, parsed.Error)

	switch status {
	case http.StatusBadRequest:
		return apperrors.NewBadRequest(internal)
	case http.StatusUnauthorized:
		return apperrors.NewUnauthorized(internal)
	case http.StatusForbidden:
		return apperrors.NewForbidden(internal)
	case http.StatusBadGateway:
		return apperrors.NewBadGateway(internal)
	case http.StatusServiceUnavailable:
		return apperrors.NewServiceUnavailable(internal)
	case http.StatusGatewayTimeout:
		return apperrors.NewGatewayTimeout(internal)
	default:
		return apperrors.NewInternal(internal)
	}
}
