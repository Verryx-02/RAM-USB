package metrics_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/metrics"
)

// Requirement: SS-F-07
func TestRun_PublishesOncePerTickUntilCanceled(t *testing.T) {
	var calls atomic.Int64

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		metrics.Run(ctx, 10*time.Millisecond, func(context.Context) error {
			calls.Add(1)
			return nil
		})
		close(done)
	}()

	// Let several ticks elapse, then stop the loop.
	time.Sleep(55 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after ctx was canceled")
	}

	got := calls.Load()
	if got < 2 {
		t.Fatalf("publish called %d times in 55ms at a 10ms interval, want at least 2", got)
	}

	// Run must not publish an unbounded burst of catch-up calls after
	// cancellation - a next read of calls shortly after done closes must
	// match what was already observed.
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != got {
		t.Fatalf("publish was called again (%d -> %d) after ctx was canceled", got, calls.Load())
	}
}

// Requirement: SS-F-07
func TestRun_DoesNotPublishImmediatelyOnStart(t *testing.T) {
	var calls atomic.Int64

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go metrics.Run(ctx, time.Hour, func(context.Context) error {
		calls.Add(1)
		return nil
	})

	// With a one-hour interval, no tick fires in this short window - Run
	// must wait for the first tick, not publish immediately on start
	// (SS-F-07: "every minute, and only").
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("publish called %d times before the first tick, want 0", got)
	}
}

// Requirement: SS-F-07
func TestRun_FailedPublishDoesNotStopTheLoop(t *testing.T) {
	var calls atomic.Int64

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		metrics.Run(ctx, 10*time.Millisecond, func(context.Context) error {
			calls.Add(1)
			return errPublishFailedForTest
		})
		close(done)
	}()

	time.Sleep(35 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after ctx was canceled")
	}

	if got := calls.Load(); got < 2 {
		t.Fatalf("publish called %d times despite always failing, want at least 2 (a transient failure must not stop the loop)", got)
	}
}

var errPublishFailedForTest = &testPublishError{}

type testPublishError struct{}

func (*testPublishError) Error() string { return "simulated publish failure" }
