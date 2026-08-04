// Package counters accumulates step-ca access-log-derived request/error/
// response-time totals (CA-F-03) into pkg/metrics.Counters, the same shape
// every other service's own request-driven counters accumulator produces
// (e.g. services/entry-hub/internal/httpapi.Counters) - the only
// difference here is the data source: an accesslog.Entry read from
// step-ca's own log stream, not a live HTTP handler invocation.
package counters

import (
	"sync"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// errorStatusThreshold is the HTTP status code at and above which a
// request counts as an error (CA-F-03's "ErrorCount"). No SRS requirement
// or design document names an exact threshold; 400 is the standard HTTP
// client/server-error boundary (RFC 9110 section 15), the same judgment call
// every other service's own handler-level isError classification makes
// implicitly by treating a 4xx/5xx response as an error case.
const errorStatusThreshold = 400

// Counters is a minimal thread-safe in-process accumulator, fed by
// accesslog.Follow's callback in cmd/metrics-sidecar/main.go and read once
// a minute by CA-F-03's metrics.Run publish loop. Record may be called
// concurrently with Snapshot (the once-a-minute publish goroutine), though
// in this sidecar's actual wiring Record is only ever called from the single
// accesslog.Follow goroutine.
//
// One mutex guards all three fields together, rather than three independent
// sync/atomic values: Snapshot divides the duration total by the request
// count, and per-field atomics let those two loads straddle a concurrent
// Record, publishing an AverageResponseTimeMs computed from a total and a
// count that never coexisted. The lock costs one uncontended acquire per
// step-ca log line, against a once-a-minute reader.
type Counters struct {
	mu              sync.Mutex
	requestCount    int64
	errorCount      int64
	totalDurationMs int64
}

// Record adds one step-ca access-log entry's status/duration to this
// accumulator's running totals.
func (c *Counters) Record(status int, durationNs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.requestCount++
	if status >= errorStatusThreshold {
		c.errorCount++
	}
	c.totalDurationMs += durationNs / int64(time.Millisecond)
}

// Snapshot converts the accumulated totals into metrics.Counters (CA-F-03's
// payload input) at the moment it's called. It does not reset the
// accumulated totals - same open reset-vs-running-total policy gap already
// documented for every other service's identical Snapshot method.
// ActiveConnections is always 0: unlike a live HTTP handler's own
// begin/end-request pair, a log line only ever describes an already-
// completed request, so this sidecar has no point-in-time "currently
// open connection" concept to report.
func (c *Counters) Snapshot() metrics.Counters {
	c.mu.Lock()
	defer c.mu.Unlock()

	var average float64
	if c.requestCount > 0 {
		average = float64(c.totalDurationMs) / float64(c.requestCount)
	}

	return metrics.Counters{
		RequestCount:          c.requestCount,
		ErrorCount:            c.errorCount,
		AverageResponseTimeMs: average,
		ActiveConnections:     0,
	}
}
