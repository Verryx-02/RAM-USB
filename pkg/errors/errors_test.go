package errors

import (
	"errors"
	"net/http"
	"testing"
)

// Requirement: DV-F-20
// Requirement: SS-F-06
// Requirement: EH-F-09
func TestAppError_ConstructorsSetStatusAndSafePublicMessage(t *testing.T) {
	internal := errors.New("internal detail: column email_hash violates unique constraint")

	cases := []struct {
		name       string
		build      func(error) *AppError
		wantStatus int
	}{
		{"bad request", NewBadRequest, http.StatusBadRequest},
		{"unauthorized", NewUnauthorized, http.StatusUnauthorized},
		{"conflict", NewConflict, http.StatusConflict},
		{"internal", NewInternal, http.StatusInternalServerError},
		{"forbidden", NewForbidden, http.StatusForbidden},
		{"bad gateway", NewBadGateway, http.StatusBadGateway},
		{"gateway timeout", NewGatewayTimeout, http.StatusGatewayTimeout},
		{"service unavailable", NewServiceUnavailable, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			appErr := tc.build(internal)

			if appErr.Status != tc.wantStatus {
				t.Fatalf("Status = %d, want %d", appErr.Status, tc.wantStatus)
			}
			if appErr.Public == "" {
				t.Fatal("Public must not be empty")
			}
			if appErr.Public == internal.Error() {
				t.Fatal("Public must not equal the internal error's detail")
			}
			if appErr.Internal != internal {
				t.Fatal("Internal must be the exact error passed in")
			}
		})
	}
}

// Requirement: DV-F-20
func TestAppError_ErrorReturnsInternalDetailOrPublicFallback(t *testing.T) {
	internal := errors.New("internal detail")

	withInternal := NewBadRequest(internal)
	if withInternal.Error() != internal.Error() {
		t.Fatalf("Error() = %q, want the internal error's message %q", withInternal.Error(), internal.Error())
	}

	withoutInternal := &AppError{Status: http.StatusBadRequest, Public: "generic message"}
	if withoutInternal.Error() != "generic message" {
		t.Fatalf("Error() = %q, want the Public message when Internal is nil", withoutInternal.Error())
	}
}

// Requirement: DV-F-20
func TestAppError_UnwrapExposesInternalError(t *testing.T) {
	sentinel := errors.New("sentinel")
	appErr := NewBadRequest(sentinel)

	if !errors.Is(appErr, sentinel) {
		t.Fatal("errors.Is should see through AppError to Internal via Unwrap")
	}
}
