package posix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// CreateUserPath is the HTTP endpoint Database-Vault calls on
// Storage-Service to request POSIX-user creation (DV-F-09/ST-F-06).
//
// No API contract for this call is specified anywhere in the SRS or in any
// design doc beyond the requirement text itself, and Storage-Service has no
// code yet (ST-F-06/ST-F-10 are unimplemented). This path, the request/
// response JSON shapes below, and the status-code convention documented on
// CreatePOSIXUser are this session's judgment call, invented so DV-F-09 has
// something concrete to call and test against a stub. Storage-Service's
// real handler (ST-F-06/ST-F-10) must match this contract when it is
// eventually built, or this contract must be revised to match it.
const CreateUserPath = "/internal/v1/posix-users"

// createUserRequest is the JSON body Database-Vault sends to Storage-Service.
type createUserRequest struct {
	Username string `json:"username"`
}

// createUserResponse is the JSON body Storage-Service is expected to send
// back, reporting the outcome of POSIX-user creation (ST-F-10).
type createUserResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ErrStorageServiceUnreachable means the HTTP/mTLS call to Storage-Service
// itself failed (connection refused, timeout, TLS handshake/organization
// rejection, context deadline, ...) - Database-Vault never got a response
// to interpret. Distinguished from ErrPOSIXUserCreationFailed so a future
// DV-F-10 handler can, if it wants, treat "we don't know what happened" and
// "Storage-Service told us it failed" differently; both are failures for
// registration purposes either way, per RD-04 fail-secure.
var ErrStorageServiceUnreachable = errors.New("posix: storage-service unreachable")

// ErrPOSIXUserCreationFailed means Database-Vault received a response from
// Storage-Service, and that response reported failure (a non-success HTTP
// status, or a decoded body with success=false).
var ErrPOSIXUserCreationFailed = errors.New("posix: storage-service reported POSIX user creation failure")

// CreatePOSIXUser asks Storage-Service, over the mTLS connection configured
// in client, to create the POSIX user named username, and waits for its
// response (DV-F-09). baseURL is Storage-Service's address (e.g.
// "https://storage-service.internal:8443"); client is expected to already
// be configured with mtls.ClientConfig so the call only completes if the
// peer's certificate carries organization="StorageService".
//
// A nil return means Storage-Service reported success. A non-nil return
// wraps either ErrStorageServiceUnreachable (the call itself did not
// complete) or ErrPOSIXUserCreationFailed (Storage-Service responded, and
// the response was a failure) - callers implementing DV-F-10 can tell
// these apart with errors.Is if needed, but must treat both as "POSIX user
// creation did not succeed" either way.
func CreatePOSIXUser(ctx context.Context, client *http.Client, baseURL string, username string) error {
	body, err := json.Marshal(createUserRequest{Username: username})
	if err != nil {
		return fmt.Errorf("posix: encode create-user request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+CreateUserPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("posix: build create-user request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageServiceUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrStorageServiceUnreachable, err)
	}

	var parsed createUserResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("%w: status %d, malformed response body: %v", ErrPOSIXUserCreationFailed, resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusCreated || !parsed.Success {
		if parsed.Error != "" {
			return fmt.Errorf("%w: status %d: %s", ErrPOSIXUserCreationFailed, resp.StatusCode, parsed.Error)
		}
		return fmt.Errorf("%w: status %d", ErrPOSIXUserCreationFailed, resp.StatusCode)
	}

	return nil
}
