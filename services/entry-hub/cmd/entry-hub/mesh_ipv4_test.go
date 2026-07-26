package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Requirement: KI-27 (docs/Known_Issues.md), EH-F-03
//
// lookupMeshIPv4 must return nil - not an error - for an interface that
// does not exist yet (the normal transient state at container startup,
// before entry-hub-mesh's sidecar has finished joining, see meshIPv4's
// own doc comment): this is a "not yet" signal, not a failure.
func TestLookupMeshIPv4_NoSuchInterface_ReturnsNil(t *testing.T) {
	if got := lookupMeshIPv4(); got != nil {
		t.Fatalf("lookupMeshIPv4() = %v, want nil (test environment has no %s interface)", got, meshInterfaceName)
	}
}

// Requirement: KI-27 (docs/Known_Issues.md), EH-F-03
//
// meshIPv4 must respect ctx cancellation rather than always blocking for
// the full meshInterfaceTimeout - a canceled context returns promptly with
// ctx.Err(), never meshIPv4's own "timed out" error, once the current poll
// attempt's interface lookup has failed.
func TestMeshIPv4_ContextCanceled_ReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := meshIPv4(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("meshIPv4() error = nil, want context.Canceled (no tailscale0 interface in this test environment)")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("meshIPv4() error = %v, want context.Canceled", err)
	}
	if elapsed > meshInterfacePollInterval {
		t.Fatalf("meshIPv4() took %s, want a prompt return well under one poll interval (%s)", elapsed, meshInterfacePollInterval)
	}
}
