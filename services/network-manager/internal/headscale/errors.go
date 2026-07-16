package headscale

import "errors"

// Sentinel errors distinguishing why CreateMeshUser/GrantStorageAccess
// failed. Neither embeds request content (email) directly in the sentinel
// itself - only in the wrapping fmt.Errorf's %w chain, which is a
// programming-error/operational detail for server-side logging, never
// echoed back to a caller as-is (internal/httpapi maps these to a fixed
// public AppError message, per CONTRIBUTING.md §7.3).
var (
	// ErrHeadscaleRequestFailed means a call to the real Headscale gRPC
	// API returned an error - unreachable server, an explicit RPC
	// error/status, or a malformed response.
	ErrHeadscaleRequestFailed = errors.New("headscale: request failed")
	// ErrMeshUserNotFound means GrantStorageAccess could not find a
	// Headscale user or mesh node for the given email - it does not
	// distinguish "user was never registered" from "node not yet
	// joined", so no distinguishing detail is leaked further up either.
	ErrMeshUserNotFound = errors.New("headscale: mesh user or node not found")
)
