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
// (NM-F-17: "every minute, and only" - exactly one publish per tick, no
// immediate publish on start, no burst catch-up for a missed tick). A
// failed publish is logged and does not stop the loop.
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
