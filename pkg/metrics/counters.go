package metrics

import (
	"sync/atomic"
	"time"
)

// RequestCounters is a minimal thread-safe in-process request/error/
// response-time tracker, feeding this package's own Counters payload with
// real traffic data instead of an always-zero placeholder. Every field is
// a sync/atomic value: BeginRequest/EndRequest/Snapshot/Track may be
// called concurrently from any number of request-handling goroutines and,
// separately, from Run's once-a-minute publish goroutine. Identical shape
// across every service that publishes metrics (EH-F-10/EH-F-11,
// SS-F-07/SS-F-08, DV-F-16/DV-F-17, ST-F-12/ST-F-13, NM-F-17/NM-F-18) - the
// per-service accumulator lives here once rather than duplicated per
// service. Certificate-Authority's own counters package is a different,
// "Record"-shaped variant fed by step-ca access-log entries rather than a
// live HTTP handler, and stays separate.
type RequestCounters struct {
	requestCount      atomic.Int64
	errorCount        atomic.Int64
	totalResponseMs   atomic.Int64
	activeConnections atomic.Int64
}

// BeginRequest marks one request as started, incrementing the
// active-connections gauge. Callers must call EndRequest exactly once for
// every BeginRequest call, typically via defer.
func (c *RequestCounters) BeginRequest() {
	c.activeConnections.Add(1)
}

// EndRequest records one completed request: its duration, whether it
// resulted in an error response, and decrements the active-connections
// gauge BeginRequest incremented.
func (c *RequestCounters) EndRequest(duration time.Duration, isError bool) {
	c.requestCount.Add(1)
	if isError {
		c.errorCount.Add(1)
	}
	c.totalResponseMs.Add(duration.Milliseconds())
	c.activeConnections.Add(-1)
}

// Track marks one request as started (BeginRequest) and returns a func to
// defer immediately at the call site: it reads *isError at defer-time
// (after the handler has had a chance to flip it) and calls EndRequest
// with the elapsed duration. This is the shared boilerplate every metrics-
// tracking call site previously duplicated inline:
//
//	isError := false
//	defer c.Track(&isError)()
//
// replaces the four-statement start-time/BeginRequest/isError/deferred-
// EndRequest block each handler used to repeat verbatim.
func (c *RequestCounters) Track(isError *bool) func() {
	start := time.Now()
	c.BeginRequest()
	return func() {
		c.EndRequest(time.Since(start), *isError)
	}
}

// Snapshot converts the accumulated counts into this package's own
// Counters payload type at the moment it's called. It does not reset the
// accumulated totals - that reset decision, if wanted, belongs to whoever
// wires Snapshot into Run, not to this type.
func (c *RequestCounters) Snapshot() Counters {
	requestCount := c.requestCount.Load()

	var average float64
	if requestCount > 0 {
		average = float64(c.totalResponseMs.Load()) / float64(requestCount)
	}

	return Counters{
		RequestCount:          requestCount,
		ErrorCount:            c.errorCount.Load(),
		AverageResponseTimeMs: average,
		ActiveConnections:     c.activeConnections.Load(),
	}
}
