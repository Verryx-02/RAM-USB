// Package pubkeylookup implements Storage-Service's calling side of ST-F-11:
// on every SSH connection attempt, sshd's AuthorizedKeysCommand (a separate,
// not-yet-built cmd/authorized-keys-command binary) needs the connecting
// user's current SSH public key, which is looked up from Database-Vault
// over mTLS. This package only builds and sends that lookup request; the
// binary that invokes it, and the mTLS-configured *http.Client it hands in,
// are a separate task's responsibility.
//
// The JSON contract here is not invented by this package: it must match
// exactly what Database-Vault's ST-F-11 server side
// (services/database-vault/internal/httpapi/pubkey_handler.go) already
// serves. PublicKeyPathPrefix and the response shape below are this
// package's own copies of that same contract (Go's internal-package import
// rule means this package cannot import database-vault's internal/httpapi
// directly, even though both services live in the same module) — if that
// contract ever changes, both sides must be updated together. This mirrors
// how services/storage-service/internal/httpapi already documents its own
// duplicated copy of the DV-F-09 create-user contract.
package pubkeylookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

// PublicKeyPathPrefix is the fixed portion of Database-Vault's ST-F-11
// lookup endpoint path; the posix username is appended directly after it.
// Must stay identical to the path shape backing
// database-vault/internal/httpapi.PublicKeyPath ("GET
// /internal/v1/public-key/{posix_username}").
const PublicKeyPathPrefix = "/internal/v1/public-key/"

// posixUsernamePattern re-validates posixUsername against DV-F-09's exact
// "user<xxxxxx>" format (six lowercase base-36 characters) before ever
// building a request — RNF-SEC-02/03's zero-trust principle applied here:
// this package does not trust its own caller to have already validated the
// value. Mirrors the identical pattern in
// database-vault/internal/httpapi/pubkey_handler.go and
// storage-service/internal/httpapi/httpapi.go.
var posixUsernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// ErrInvalidPosixUsername means posixUsername failed this package's own
// structural re-validation; no HTTP call is attempted.
var ErrInvalidPosixUsername = errors.New("pubkeylookup: invalid posix username")

// ErrPublicKeyNotFound means Database-Vault responded with HTTP 404: the
// posix username is well-formed but has no ssh_public_key on record. This
// is a distinct, legitimate outcome (see pubkey_handler.go's doc comment
// for why a 404 is safe and meaningful here, unlike DV-F-15's login-lookup
// pattern), not a call failure — callers should deny the SSH connection
// (RD-04, fail-secure) but may log this differently from ErrLookupFailed.
var ErrPublicKeyNotFound = errors.New("pubkeylookup: no public key on record for posix username")

// ErrLookupFailed means the call to Database-Vault itself did not complete
// successfully: a network/TLS-level failure, a context deadline, an
// unexpected HTTP status other than 200/404, or a response body that could
// not be parsed as the expected JSON shape. Callers should deny the SSH
// connection (RD-04, fail-secure) the same as for ErrPublicKeyNotFound, but
// may log this differently since it signals the lookup itself is
// untrustworthy rather than a confirmed "no key" answer.
var ErrLookupFailed = errors.New("pubkeylookup: public key lookup failed")

// publicKeyResponse is the JSON body Database-Vault sends back on HTTP 200.
// Must stay identical in shape to database-vault/internal/httpapi's
// publicKeyResponse.
type publicKeyResponse struct {
	SSHPublicKey string `json:"ssh_public_key"`
}

// FetchAuthorizedKeysLine asks Database-Vault, over the mTLS connection
// configured in client, for posixUsername's current SSH public key
// (ST-F-11). baseURL is Database-Vault's dedicated public-key-lookup
// address (e.g. "https://database-vault.internal:8444"); client is expected
// to already be configured with mtls.ClientConfig so the call only
// completes if the peer's certificate carries organization="StorageService".
//
// ctx controls the request's deadline/cancellation; this function sets no
// timeout of its own, since the caller (the AuthorizedKeysCommand binary)
// owns its own latency budget.
//
// On success, returns the raw ssh_public_key string. On failure, returns an
// error wrapping either ErrInvalidPosixUsername (rejected before any HTTP
// call), ErrPublicKeyNotFound (Database-Vault responded HTTP 404), or
// ErrLookupFailed (any other failure) — see their doc comments for how
// callers should treat each.
func FetchAuthorizedKeysLine(ctx context.Context, client *http.Client, baseURL, posixUsername string) (string, error) {
	if !posixUsernamePattern.MatchString(posixUsername) {
		return "", ErrInvalidPosixUsername
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+PublicKeyPathPrefix+posixUsername, nil)
	if err != nil {
		return "", fmt.Errorf("%w: build request: %v", ErrLookupFailed, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrLookupFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return "", ErrPublicKeyNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: unexpected status %d", ErrLookupFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: read response: %v", ErrLookupFailed, err)
	}

	var parsed publicKeyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("%w: malformed response body: %v", ErrLookupFailed, err)
	}

	return parsed.SSHPublicKey, nil
}
