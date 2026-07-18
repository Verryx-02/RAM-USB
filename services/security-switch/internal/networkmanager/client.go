// Package networkmanager implements Security-Switch's two outbound mTLS
// calls to Network-Manager: GrantAccess (SS-F-05), after a successful
// login, requesting that the given user be granted access to
// Storage-Service for 12 hours; and CreateMeshUser (SS-F-09), after a
// successful registration, requesting a dedicated Headscale user and a
// pre-auth key for the new account (UC-01 steps 7-8).
//
// The user is identified to Network-Manager by email in both calls, not a
// Database-Vault-issued identifier: per UC-02 and SRS 2.6, the login-time
// grant is a server-side ACL tag applied to the user's already-existing
// mesh node (joined once, at registration, via CreateMeshUser's own
// pre-auth key), and Security-Switch already holds the caller's email from
// the request it is forwarding in both flows - it never needs
// Database-Vault to echo one back.
//
// GrantPath/grantRequest/grantResponse were this package's own invented,
// documented contract when Network-Manager had no code at all
// (NM-F-08/NM-F-09 were unimplemented); Network-Manager's real handler
// (services/network-manager/internal/httpapi/handler.go) now exists and
// was confirmed, by reading it directly, to match this contract exactly.
// MeshUserPath/meshUserRequest/meshUserResponse reproduce that same,
// already-real handler's MeshUserPath contract - not invented here, this
// package is the first caller of an endpoint Network-Manager's own task
// deliberately anticipated and left unwired.
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

// MeshUserPath is the endpoint Security-Switch calls on Network-Manager,
// after a successful registration, to request a dedicated Headscale user
// and a pre-auth key for the new account (SS-F-09). This reproduces
// Network-Manager's own already-committed, documented contract exactly
// (services/network-manager/internal/httpapi/handler.go's MeshUserPath/
// meshUserRequest/meshUserResponse) - confirmed by reading that file
// directly this session, not invented here. If it ever needs to change,
// change both sides by hand; no shared type exists across these two
// services' internal packages (the same limitation already documented for
// GrantPath/grantRequest/grantResponse above).
const MeshUserPath = "/internal/v1/mesh-users"

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

// meshUserRequest is the JSON body Security-Switch sends to Network-Manager
// for SS-F-09, reproducing Network-Manager's own meshUserRequest exactly.
type meshUserRequest struct {
	Email string `json:"email"`
}

// meshUserResponse is the JSON body Network-Manager is expected to send
// back for SS-F-09, reproducing Network-Manager's own meshUserResponse
// exactly.
type meshUserResponse struct {
	Success    bool   `json:"success"`
	PreAuthKey string `json:"pre_auth_key,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Sentinel errors distinguishing why GrantAccess or CreateMeshUser failed.
// None of these embed request content.
var (
	// ErrNetworkManagerUnreachable means the HTTP/mTLS call itself did not
	// complete. Shared by GrantAccess (SS-F-05) and CreateMeshUser
	// (SS-F-09): both talk to the same Network-Manager over the same
	// mTLS-configured client, so a transport-level failure is the same
	// category of problem regardless of which operation was in flight.
	ErrNetworkManagerUnreachable = errors.New("networkmanager: unreachable")
	// ErrNetworkManagerTimeout means the call did not complete before its
	// context deadline elapsed. Shared by GrantAccess and CreateMeshUser,
	// same reasoning as ErrNetworkManagerUnreachable above.
	ErrNetworkManagerTimeout = errors.New("networkmanager: timed out waiting for response")
	// ErrGrantDenied means Network-Manager responded, but explicitly
	// refused the grant (HTTP 403, or any status other than 200/201 with
	// success=false) - a case the caller (internal/httpapi) maps to HTTP
	// 403 (SS-F-06), distinct from ErrNetworkManagerUnreachable's 502/504.
	ErrGrantDenied = errors.New("networkmanager: grant request denied")
	// ErrMeshUserCreationDenied means Network-Manager responded, but
	// explicitly refused to create a mesh user/pre-auth key (HTTP 403, or
	// any status other than 200/201 with success=false) for SS-F-09's
	// registration-time call. Kept distinct from ErrGrantDenied (a
	// different operation, a different point in the request lifecycle -
	// registration vs. login) even though both currently map to the same
	// HTTP 403 at Security-Switch's own boundary, so a future divergence
	// in how the two failures should be handled doesn't require
	// disentangling one sentinel used for two purposes.
	ErrMeshUserCreationDenied = errors.New("networkmanager: mesh user creation request denied")
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

	// A 5xx status means Network-Manager itself failed to process the
	// request (its own internal error, or the request never reached its
	// handling logic) - this is the same "the call did not complete as a
	// real answer" category ErrNetworkManagerUnreachable's doc comment
	// already claims, distinct from a considered 403 refusal. Checked
	// before the malformed-body branch below: a 5xx response's body is
	// commonly a plain-text error page or empty, not JSON, and treating
	// that as ErrGrantDenied would misreport a Network-Manager outage as
	// "the user's grant was denied."
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("%w: status %d", ErrNetworkManagerUnreachable, resp.StatusCode)
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

// CreateMeshUser asks Network-Manager, over the mTLS connection configured
// in client, to create a dedicated Headscale user and generate a pre-auth
// key for the given email (SS-F-09) - called once, after Database-Vault
// confirms a successful registration (UC-01 step 7). A nil error returns
// the pre-auth key to include in the response Security-Switch sends back
// up to Entry-Hub (UC-01 step 8).
func CreateMeshUser(ctx context.Context, client *http.Client, baseURL string, email string) (string, error) {
	body, err := json.Marshal(meshUserRequest{Email: email})
	if err != nil {
		return "", fmt.Errorf("networkmanager: encode mesh user request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+MeshUserPath, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("networkmanager: build mesh user request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", fmt.Errorf("%w: %v", ErrNetworkManagerTimeout, err)
		}
		return "", fmt.Errorf("%w: %v", ErrNetworkManagerUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: read response: %v", ErrNetworkManagerUnreachable, err)
	}

	// Same reasoning as GrantAccess above: a 5xx status is Network-
	// Manager's own failure to process the request, not a considered
	// refusal, and is checked before the malformed-body branch below for
	// the same reason (a 5xx body is commonly not JSON at all).
	if resp.StatusCode >= http.StatusInternalServerError {
		return "", fmt.Errorf("%w: status %d", ErrNetworkManagerUnreachable, resp.StatusCode)
	}

	var parsed meshUserResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("%w: status %d, malformed response body: %v", ErrMeshUserCreationDenied, resp.StatusCode, err)
	}

	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w: status %d", ErrMeshUserCreationDenied, resp.StatusCode)
	}
	if (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated) || !parsed.Success {
		if parsed.Error != "" {
			return "", fmt.Errorf("%w: status %d: %s", ErrMeshUserCreationDenied, resp.StatusCode, parsed.Error)
		}
		return "", fmt.Errorf("%w: status %d", ErrMeshUserCreationDenied, resp.StatusCode)
	}

	return parsed.PreAuthKey, nil
}
