package httpapi

import (
	"sync/atomic"
	"time"

	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/metrics"
)

// Counters is a minimal thread-safe in-process request/error/response-time
// tracker, feeding NM-F-17/NM-F-18's metrics.Counters with real traffic
// data. Identical shape to Database-Vault's own httpapi.Counters
// (DV-F-16/DV-F-17) - every field is a sync/atomic value: Record and
// Snapshot may be called concurrently from any number of request-handling
// goroutines and, separately, from metrics.Run's once-a-minute publish
// goroutine.
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
// (NM-F-17/NM-F-18's payload input) at the moment it's called. Does not
// reset the accumulated totals - same running-total convention as
// Database-Vault's own Snapshot.
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
