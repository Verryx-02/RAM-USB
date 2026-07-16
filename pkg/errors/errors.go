// Package errors provides the structured error type every RAM-USB HTTP
// boundary uses to respond to a client. Per CONTRIBUTING.md §7.3
// (EH-F-09, SS-F-06, DV-F-20, ST-F-*), a client must only ever see a
// fixed, safe public message bound to the response's HTTP status code —
// never the internal error detail (which field failed validation, which
// database constraint fired, ...). AppError carries both: the public
// message a handler writes to the response body, and the internal error a
// handler logs, so a single value is the one thing a handler needs to
// satisfy both "sanitized to the client" and "detailed in the log."
//
// The public message is fixed per status code inside each constructor
// (NewBadRequest, NewUnauthorized, NewConflict, NewInternal) rather than
// left for a caller to supply — this guarantees the public message is
// always the safe one for that status code, never accidentally built from
// caller-supplied detail.
package errors

import "net/http"

// AppError is a structured error carrying a fixed, safe public message
// for a given HTTP status code, plus the full internal error for logging.
type AppError struct {
	// Status is the HTTP status code the response is written with.
	Status int

	// Public is the fixed, safe message the response body carries. It
	// never contains any content from Internal.
	Public string

	// Internal is the full underlying error, for logging only. A handler
	// must never write Internal (or its content) into an HTTP response
	// body.
	Internal error
}

// Error implements the error interface, returning the internal detail —
// AppError is meant to be logged via this method (or by logging Internal
// directly), never written to a response body via it.
func (e *AppError) Error() string {
	if e.Internal == nil {
		return e.Public
	}
	return e.Internal.Error()
}

// Unwrap lets errors.Is/errors.As see through AppError to the sentinel
// error it wraps.
func (e *AppError) Unwrap() error {
	return e.Internal
}

// NewBadRequest builds an AppError for HTTP 400: a request that failed
// validation or decoding (EH-F-06, SS-F-03, DV-F-20). The public message
// deliberately does not say which field or rule failed.
func NewBadRequest(internal error) *AppError {
	return &AppError{
		Status:   http.StatusBadRequest,
		Public:   "the request could not be processed",
		Internal: internal,
	}
}

// NewUnauthorized builds an AppError for HTTP 401: a failed authentication
// attempt (DV-F-15). The public message deliberately does not say whether
// the email or the password was the cause.
func NewUnauthorized(internal error) *AppError {
	return &AppError{
		Status:   http.StatusUnauthorized,
		Public:   "authentication failed",
		Internal: internal,
	}
}

// NewConflict builds an AppError for HTTP 409: a duplicate registration
// (DV-F-12). The public message deliberately does not say which field
// (email or SSH key) collided.
func NewConflict(internal error) *AppError {
	return &AppError{
		Status:   http.StatusConflict,
		Public:   "the request could not be completed",
		Internal: internal,
	}
}

// NewInternal builds an AppError for HTTP 500: any failure that is not a
// client-side validation, authentication, or duplicate-data problem (e.g.
// a database or downstream-service failure). The public message
// deliberately gives no operational detail.
func NewInternal(internal error) *AppError {
	return &AppError{
		Status:   http.StatusInternalServerError,
		Public:   "the request could not be completed",
		Internal: internal,
	}
}

// NewForbidden builds an AppError for HTTP 403: a downstream component
// explicitly refused an otherwise-well-formed, otherwise-authenticated
// request (SS-F-06), e.g. Network-Manager declining to grant Storage-Service
// access. The public message deliberately does not say which component or
// policy refused it.
func NewForbidden(internal error) *AppError {
	return &AppError{
		Status:   http.StatusForbidden,
		Public:   "the request was refused",
		Internal: internal,
	}
}

// NewBadGateway builds an AppError for HTTP 502: an outbound mTLS call to a
// downstream internal service (e.g. Security-Switch calling Database-Vault
// or Network-Manager, SS-F-04/SS-F-05) did not complete - connection
// refused, TLS/organization rejection, or a response this service does not
// recognize - as distinct from that service completing the call and
// reporting its own failure. The public message deliberately gives no
// operational detail.
func NewBadGateway(internal error) *AppError {
	return &AppError{
		Status:   http.StatusBadGateway,
		Public:   "the request could not be completed",
		Internal: internal,
	}
}

// NewGatewayTimeout builds an AppError for HTTP 504: an outbound mTLS call
// to a downstream internal service did not complete within its deadline
// (SS-F-06). The public message deliberately gives no operational detail.
func NewGatewayTimeout(internal error) *AppError {
	return &AppError{
		Status:   http.StatusGatewayTimeout,
		Public:   "the request could not be completed",
		Internal: internal,
	}
}

// NewServiceUnavailable builds an AppError for HTTP 503: an outbound call
// to a downstream internal service (e.g. Entry-Hub calling Security-Switch,
// EH-F-09) did not complete before its deadline. EH-F-09's fixed status
// set (400/401/500/502/503) uses 503 where Security-Switch's own SS-F-06
// set uses 504 for the same "call timed out" case - a deliberate
// per-component difference in the SRS, not a typo to reconcile; do not
// merge this with NewGatewayTimeout. The public message deliberately
// gives no operational detail.
func NewServiceUnavailable(internal error) *AppError {
	return &AppError{
		Status:   http.StatusServiceUnavailable,
		Public:   "the request could not be completed",
		Internal: internal,
	}
}
