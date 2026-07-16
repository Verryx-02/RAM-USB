// Package networkmanager implements Security-Switch's outbound mTLS call
// to Network-Manager (SS-F-05): after a successful login, request that the
// given user be granted access to Storage-Service for 12 hours.
//
// The user is identified to Network-Manager by email, not a Database-Vault-
// issued identifier: per UC-02 and SRS 2.6, the user's mesh node already
// exists (joined once, at registration, via UC-01 step 8's pre-auth key),
// so the grant is a server-side ACL tag applied to that existing node, and
// Security-Switch already holds the caller's email from the login request
// it is forwarding - it never needs Database-Vault to echo one back.
//
// Network-Manager has no code yet (NM-F-08/NM-F-09 are unimplemented) - the
// endpoint path, request/response JSON shapes, and status-code convention
// below are this session's invented, documented judgment call, the exact
// same "invented but documented" pattern as Database-Vault's DV-F-09
// Storage-Service contract (services/database-vault/internal/posix/
// client.go). Network-Manager's real handler (NM-F-09) must match this
// contract when it is eventually built, or this contract must be revised
// to match it.
package networkmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GrantPath is the endpoint Security-Switch calls on Network-Manager to
// request a 12-hour Storage-Service access grant for a user (SS-F-05).
const GrantPath = "/internal/v1/grants"

// GrantDuration is the fixed access window SS-F-05 specifies literally:
// "grant that user access to Storage-Service for 12 hours".
const GrantDuration = 12 * time.Hour

// OrganizationNetworkManager is the required Subject.Organization value on
// Network-Manager's server certificate (SS-F-05: "over mTLS"). No literal
// `organization="..."` value is given anywhere in the SRS for this
// direction - this session's judgment call, following the same
// PascalCase-no-hyphen convention as dbvault.OrganizationDatabaseVault.
const OrganizationNetworkManager = "NetworkManager"

// grantRequest is the JSON body Security-Switch sends to Network-Manager.
// Email identifies the user whose already-existing mesh node (joined at
// registration via UC-01 step 8's pre-auth key) should receive the ACL
// grant. Security-Switch already holds this value from the login request
// it is forwarding (validation.LoginRequest.Email, decoded before
// Database-Vault is even called) - it does not come from Database-Vault's
// response.
type grantRequest struct {
	Email           string `json:"email"`
	DurationSeconds int64  `json:"duration_seconds"`
}

// grantResponse is the JSON body Network-Manager is expected to send back.
type grantResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Sentinel errors distinguishing why GrantAccess failed. None of these
// embed request content.
var (
	// ErrNetworkManagerUnreachable means the HTTP/mTLS call itself did not
	// complete.
	ErrNetworkManagerUnreachable = errors.New("networkmanager: unreachable")
	// ErrNetworkManagerTimeout means the call did not complete before its
	// context deadline elapsed.
	ErrNetworkManagerTimeout = errors.New("networkmanager: timed out waiting for response")
	// ErrGrantDenied means Network-Manager responded, but explicitly
	// refused the grant (HTTP 403, or any status other than 200/201 with
	// success=false) - a case the caller (internal/httpapi) maps to HTTP
	// 403 (SS-F-06), distinct from ErrNetworkManagerUnreachable's 502/504.
	ErrGrantDenied = errors.New("networkmanager: grant request denied")
)

// GrantAccess asks Network-Manager, over the mTLS connection configured in
// client, to grant the user identified by email access to Storage-Service
// for GrantDuration (SS-F-05). A nil return means the grant succeeded.
func GrantAccess(ctx context.Context, client *http.Client, baseURL string, email string) error {
	body, err := json.Marshal(grantRequest{
		Email:           email,
		DurationSeconds: int64(GrantDuration.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("networkmanager: encode grant request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+GrantPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("networkmanager: build grant request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %v", ErrNetworkManagerTimeout, err)
		}
		return fmt.Errorf("%w: %v", ErrNetworkManagerUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read response: %v", ErrNetworkManagerUnreachable, err)
	}

	var parsed grantResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("%w: status %d, malformed response body: %v", ErrGrantDenied, resp.StatusCode, err)
	}

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: status %d", ErrGrantDenied, resp.StatusCode)
	}
	if (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated) || !parsed.Success {
		if parsed.Error != "" {
			return fmt.Errorf("%w: status %d: %s", ErrGrantDenied, resp.StatusCode, parsed.Error)
		}
		return fmt.Errorf("%w: status %d", ErrGrantDenied, resp.StatusCode)
	}

	return nil
}
