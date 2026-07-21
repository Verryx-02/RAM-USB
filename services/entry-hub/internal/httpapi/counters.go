package httpapi

import (
	"sync/atomic"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// Counters is a minimal thread-safe in-process request/error/response-time
// tracker, feeding EH-F-10/EH-F-11's metrics.Counters with real traffic
// data instead of an always-zero placeholder. Every field is a sync/atomic
// value: BeginRequest/EndRequest/Snapshot may be called concurrently from
// any number of request-handling goroutines and, separately, from
// metrics.Run's once-a-minute publish goroutine. Mirrors
// services/security-switch/internal/httpapi/counters.go exactly, retagged
// for EH-F-10/EH-F-11.
type Counters struct {
	requestCount      atomic.Int64
	errorCount        atomic.Int64
	totalResponseMs   atomic.Int64
	activeConnections atomic.Int64
}

// BeginRequest marks one request as started, incrementing the
// active-connections gauge. Callers must call EndRequest exactly once for
// every BeginRequest call, typically via defer.
func (c *Counters) BeginRequest() {
	c.activeConnections.Add(1)
}

// EndRequest records one completed request: its duration, whether it
// resulted in an error response, and decrements the active-connections
// gauge BeginRequest incremented.
func (c *Counters) EndRequest(duration time.Duration, isError bool) {
	c.requestCount.Add(1)
	if isError {
		c.errorCount.Add(1)
	}
	c.totalResponseMs.Add(duration.Milliseconds())
	c.activeConnections.Add(-1)
}

// Snapshot converts the accumulated counts into metrics.Counters
// (EH-F-10/EH-F-11's payload input) at the moment it's called. It does not
// reset the accumulated totals - same open reset-vs-running-total policy
// gap already documented for Security-Switch's identical Snapshot.
func (c *Counters) Snapshot() metrics.Counters {
	requestCount := c.requestCount.Load()

	var average float64
	if requestCount > 0 {
		average = float64(c.totalResponseMs.Load()) / float64(requestCount)
	}

	return metrics.Counters{
		RequestCount:          requestCount,
		ErrorCount:            c.errorCount.Load(),
		AverageResponseTimeMs: average,
		ActiveConnections:     c.activeConnections.Load(),
	}
}
