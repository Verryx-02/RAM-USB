package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	errTestUnreachable = errors.New("httpclient: test unreachable")
	errTestTimeout     = errors.New("httpclient: test timeout")
)

type postRequest struct {
	Value string `json:"value"`
}

// Requirement: SS-F-04
// Requirement: SS-F-05
func TestPost_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	body, status, err := Post(context.Background(), srv.Client(), srv.URL, postRequest{Value: "x"}, errTestUnreachable, errTestTimeout)
	if err != nil {
		t.Fatalf("Post() error = %v, want nil", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("body = %q, want %q", body, `{"status":"ok"}`)
	}
}

// Requirement: SS-F-06
func TestPost_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close() // closed before use: the peer is unreachable

	_, _, err := Post(context.Background(), srv.Client(), srv.URL, postRequest{Value: "x"}, errTestUnreachable, errTestTimeout)
	if !errors.Is(err, errTestUnreachable) {
		t.Fatalf("Post() error = %v, want errTestUnreachable", err)
	}
}

// Requirement: SS-F-06
func TestPost_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, _, err := Post(ctx, srv.Client(), srv.URL, postRequest{Value: "x"}, errTestUnreachable, errTestTimeout)
	if !errors.Is(err, errTestTimeout) {
		t.Fatalf("Post() error = %v, want errTestTimeout", err)
	}
}
