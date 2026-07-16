package metrics

import (
	"context"
	"log/slog"
	"time"
)

// PublishFunc performs one publish cycle. PublishOnce, bound to a real
// Publisher and a real counters source, is the production PublishFunc
// Run is called with.
type PublishFunc func(ctx context.Context) error

// Run calls publish once per interval tick, until ctx is canceled
// (SS-F-07: "every minute, and only" - exactly one publish per tick, no
// immediate publish on start, no burst catch-up for a missed tick, since
// time.Ticker drops ticks it could not deliver promptly). A failed
// publish is logged and does not stop the loop: a transient broker
// outage should not permanently end metrics publishing for the rest of
// the process's lifetime.
//
// This function only wires the interval; the single-publish-cycle logic
// it calls (PublishOnce) is tested directly and separately, since
// exercising a real one-minute wait in a test is impractical.
func Run(ctx context.Context, interval time.Duration, publish PublishFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := publish(ctx); err != nil {
				slog.Error("metrics: publish cycle failed", "error", err)
			}
		}
	}
}
