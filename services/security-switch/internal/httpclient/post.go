// Package httpclient holds the HTTP mechanics shared by Security-Switch's
// two outbound mTLS clients (internal/dbvault's SS-F-04 call to
// Database-Vault, and internal/networkmanager's SS-F-05/SS-F-09 calls to
// Network-Manager): marshal a JSON body, POST it, read the response, and
// classify a transport-level failure as either a timeout or an
// unreachable-peer error. Each caller keeps its own request/response shape
// and its own application-level error mapping (an unexpected status code,
// an explicit denial, ...) - this package only does the part that was
// identical, byte for byte, in all three call sites.
//
// This package never constructs or configures the *http.Client it is
// given - mTLS/organization verification (SS-F-04's "the certificate comes
// from a Database-Vault", SS-F-05's "over mTLS") stays exactly where it
// already lived: the *http.Client built once in each service's own
// cmd/.../main.go via pkg/mtls.ClientConfig. Post only ever calls
// client.Do on the client it receives.
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Post marshals body as JSON, POSTs it to url over client, and returns the
// raw response bytes and status code. Any failure short of receiving a
// complete HTTP response is reported wrapping unreachable, or wrapping
// timeout instead if the failure was specifically a context deadline.
//
// unreachable and timeout are the caller's own sentinel errors (e.g.
// dbvault.ErrDatabaseVaultUnreachable/ErrDatabaseVaultTimeout,
// networkmanager.ErrNetworkManagerUnreachable/ErrNetworkManagerTimeout) so
// errors.Is checks against a caller's specific sentinel keep working
// unchanged after this call returns.
func Post(ctx context.Context, client *http.Client, url string, body any, unreachable, timeout error) ([]byte, int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("httpclient: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, fmt.Errorf("httpclient: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, 0, fmt.Errorf("%w: %w", timeout, err)
		}
		return nil, 0, fmt.Errorf("%w: %w", unreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read response: %w", unreachable, err)
	}

	return respBody, resp.StatusCode, nil
}
