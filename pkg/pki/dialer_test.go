package pki

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Requirement: NET-F-01, NM-F-04
//
// RouteThroughDialer installs dial as both DialContext and (when the SDK
// set one, as it always does for a real BootstrapClient result -
// see dialer.go) a replacement DialTLSContext, rather than leaving the
// original DialTLSContext in place - which would otherwise silently take
// priority over DialContext for every HTTPS request (net/http's own
// documented behavior), making an installed DialContext alone a no-op.
func TestRouteThroughDialer_InstallsDialer(t *testing.T) {
	originalTLSDialCalled := false
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, //nolint:gosec // test fixture, not a real handshake
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			originalTLSDialCalled = true
			return nil, errors.New("original DialTLSContext must never be invoked once RouteThroughDialer runs")
		},
	}
	client := &http.Client{Transport: transport}

	var dialCalled int32
	wantErr := errors.New("fake dialer invoked")
	fakeDial := DialFunc(func(context.Context, string, string) (net.Conn, error) {
		atomic.AddInt32(&dialCalled, 1)
		return nil, wantErr
	})

	if err := RouteThroughDialer(client, fakeDial); err != nil {
		t.Fatalf("RouteThroughDialer() error = %v, want nil", err)
	}

	if transport.DialTLSContext == nil {
		t.Fatal("RouteThroughDialer() left DialTLSContext nil, want a replacement dialer")
	}

	// Exercise the installed DialTLSContext directly - the real dial path
	// an actual HTTPS request through this transport would take (proves
	// fakeDial is wired in, not just installed and silently ignored).
	_, err := transport.DialTLSContext(context.Background(), "tcp", "certificate-authority:9000")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DialTLSContext() error = %v, want %v (from the fake dialer)", err, wantErr)
	}
	if atomic.LoadInt32(&dialCalled) != 1 {
		t.Fatalf("fake dialer invocation count = %d, want 1", dialCalled)
	}
	if originalTLSDialCalled {
		t.Fatal("original DialTLSContext was invoked; RouteThroughDialer must fully replace it, not chain to it")
	}
}

// Requirement: NET-F-01, NM-F-04
//
// A DialContext-only SDK transport (DialTLSContext left nil - not what
// BootstrapClient produces today, but RouteThroughDialer's own doc
// comment promises to stay correct if a future SDK version stops setting
// one) still gets routed correctly through plain DialContext.
func TestRouteThroughDialer_NoExistingDialTLSContext(t *testing.T) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}} //nolint:gosec // test fixture
	client := &http.Client{Transport: transport}

	var dialCalled int32
	fakeDial := DialFunc(func(context.Context, string, string) (net.Conn, error) {
		atomic.AddInt32(&dialCalled, 1)
		return nil, errors.New("fake dialer invoked")
	})

	if err := RouteThroughDialer(client, fakeDial); err != nil {
		t.Fatalf("RouteThroughDialer() error = %v, want nil", err)
	}
	if transport.DialTLSContext != nil {
		t.Fatal("RouteThroughDialer() set DialTLSContext when the SDK transport had none, want it left nil")
	}

	if _, err := transport.DialContext(context.Background(), "tcp", "certificate-authority:9000"); err == nil {
		t.Fatal("DialContext() error = nil, want the fake dialer's error")
	}
	if atomic.LoadInt32(&dialCalled) != 1 {
		t.Fatalf("fake dialer invocation count = %d, want 1", dialCalled)
	}
}

// Requirement: RD-04
//
// RouteThroughDialer fails loud, not silently, when client.Transport
// isn't the concrete *http.Transport this package's own investigation of
// the pinned smallstep/certificates@v0.30.2 source found BootstrapClient
// always returns (see dialer.go's doc comment) - proving the fallback for
// that undocumented assumption breaking is a clear error, never a panic
// or a silent no-op that leaves traffic unrouted.
func TestRouteThroughDialer_RejectsUnexpectedTransportType(t *testing.T) {
	client := &http.Client{Transport: noopRoundTripper{}}

	err := RouteThroughDialer(client, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial must never be invoked when installation itself fails")
		return nil, nil
	})
	if !errors.Is(err, ErrUnexpectedTransportType) {
		t.Fatalf("RouteThroughDialer() error = %v, want %v", err, ErrUnexpectedTransportType)
	}
}

// Requirement: CA-F-04
//
// NewClientWithDialer with a nil dial is a pure regression check: it must
// behave exactly like NewClient's existing malformed-token error path
// (TestNewClient_MalformedToken), since NewClient is now defined in terms
// of this function.
func TestNewClientWithDialer_NilDialerMatchesNewClient(t *testing.T) {
	_, err := NewClientWithDialer(context.Background(), "not-a-real-token", nil)
	if err == nil {
		t.Fatal("NewClientWithDialer() with a malformed token and a nil dialer error = nil, want non-nil")
	}
}

// Requirement: NET-F-01, NM-F-04
//
// NewServerWithDialer rejects any non-nil dialer before ever attempting a
// real network call (RD-04, fail-secure) - the malformed token here would
// also fail on its own, but this test's point is that the dialer
// rejection happens first and unconditionally, not only when a real CA
// bootstrap would otherwise have succeeded.
func TestNewServerWithDialer_RejectsDialer(t *testing.T) {
	fakeDial := DialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dial must never be invoked; NewServerWithDialer must reject before attempting any network call")
		return nil, nil
	})

	_, err := NewServerWithDialer(context.Background(), "not-a-real-token", &http.Server{ReadHeaderTimeout: 5 * time.Second}, fakeDial)
	if !errors.Is(err, ErrServerDialerUnsupported) {
		t.Fatalf("NewServerWithDialer() error = %v, want %v", err, ErrServerDialerUnsupported)
	}
}

// Requirement: CA-F-04
//
// NewServerWithDialer with a nil dial is a pure regression check, mirroring
// TestNewClientWithDialer_NilDialerMatchesNewClient.
func TestNewServerWithDialer_NilDialerMatchesNewServer(t *testing.T) {
	_, err := NewServerWithDialer(context.Background(), "not-a-real-token", &http.Server{ReadHeaderTimeout: 5 * time.Second}, nil)
	if err == nil {
		t.Fatal("NewServerWithDialer() with a malformed token and a nil dialer error = nil, want non-nil")
	}
}
