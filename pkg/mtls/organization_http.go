package mtls

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RequireOrganization and WrapRoundTripper are the HTTP-request-level
// counterparts of ServerConfig/ClientConfig's handshake-level organization
// check (PKI-F-02), for services whose *tls.Config is built by pkg/pki
// (CA-F-04's bootstrap client/server) rather than by ServerConfig/
// ClientConfig. pkg/pki's underlying ca.BootstrapServer/BootstrapClient
// hard-error if a *tls.Config with a VerifyConnection callback is already
// set, and expose no hook to install one - see pkg/pki's package doc
// comment. net/http always populates Request.TLS (server side) and
// Response.TLS (client side) from the completed handshake regardless of
// which library built the tls.Config, so the same check ServerConfig/
// ClientConfig perform inside VerifyConnection can run one layer up, at the
// HTTP boundary, instead.

// appErrorBody is the JSON body written on rejection, matching the
// {"error": "..."} envelope every other HTTP boundary in this codebase
// writes via its own writeAppError (see e.g.
// services/database-vault/internal/httpapi/handler.go) - this package has
// no dependency on pkg/errors (avoiding a dependency edge back toward a
// package that itself may, in the future, want to depend on pkg/mtls), so
// it reproduces the same minimal envelope locally rather than importing
// pkg/errors.AppError for two call sites.
type appErrorBody struct {
	Error string `json:"error"`
}

// writeForbidden writes HTTP 403 with a fixed, safe public message - no
// detail about which organization was expected or received ever reaches
// the response body.
func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(appErrorBody{Error: "the request was refused"})
}

// RequireOrganization returns http.Handler middleware that denies (RD-04,
// fail-secure) any request whose r.TLS is nil or has no verified peer
// certificate chain, or whose peer leaf certificate's Subject.Organization
// does not contain allowedOrganization, and otherwise calls next.
//
// r.TLS.VerifiedChains, not r.TLS.PeerCertificates, backs this check - the
// same choice verifyOrganization (mtls.go) makes and for the same reason:
// VerifiedChains is the chain crypto/tls has already cryptographically
// verified against the server's configured client-CA pool, populated when
// Config.ClientAuth is RequireAndVerifyClientCert (exactly the mode
// ca.BootstrapServer configures by default - confirmed by reading
// github.com/smallstep/certificates/ca/tls.go), not merely whatever
// certificate the peer happened to present.
func RequireOrganization(allowedOrganization string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeForbidden(w)
			return
		}

		leaf, err := verifiedLeaf(*r.TLS)
		if err != nil {
			writeForbidden(w)
			return
		}

		if err := checkOrganization(leaf, allowedOrganization); err != nil {
			writeForbidden(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// organizationRoundTripper is WrapRoundTripper's implementation.
type organizationRoundTripper struct {
	next                http.RoundTripper
	allowedOrganization string
}

// WrapRoundTripper returns an http.RoundTripper that performs the request
// via next (e.g. pki.NewClient's returned *http.Client.Transport) and then
// rejects - returning an error instead of the response, never handing it
// back to the caller (RD-04, fail-secure) - any response whose Response.TLS
// is nil or has no verified peer certificate chain, or whose peer leaf
// certificate's Subject.Organization does not contain allowedOrganization.
// next defaults to http.DefaultTransport if nil, matching
// http.Client.Transport's own nil-means-default convention.
func WrapRoundTripper(next http.RoundTripper, allowedOrganization string) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &organizationRoundTripper{next: next, allowedOrganization: allowedOrganization}
}

// RoundTrip implements http.RoundTripper.
func (rt *organizationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.TLS == nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("mtls: response has no TLS connection state")
	}

	leaf, err := verifiedLeaf(*resp.TLS)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}

	if err := checkOrganization(leaf, rt.allowedOrganization); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}

	return resp, nil
}
