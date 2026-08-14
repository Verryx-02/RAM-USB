package main

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/httpapi"
)

// verifies the mux only accepts POST on this internal path
func TestNewMux_RejectsNonPOSTWithMethodNotAllowed(t *testing.T) {
	mux := newMux(&httpapi.Handler{})

	for _, path := range []string{httpapi.RegisterPath, httpapi.LoginPath} {
		req := httptest.NewRequestWithContext(context.Background(), "GET", path, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != 405 {
			t.Errorf("GET %s: got status %d, want 405", path, rec.Code)
		}
	}
}
