package metrics

import (
	"testing"
	"time"
)

// Requirement: EH-F-10
// Requirement: EH-F-11
func TestRequestCounters_SnapshotReflectsRecordedRequests(t *testing.T) {
	c := &RequestCounters{}

	c.BeginRequest()
	c.EndRequest(10*time.Millisecond, false)

	c.BeginRequest()
	c.EndRequest(30*time.Millisecond, true)

	got := c.Snapshot()

	if got.RequestCount != 2 {
		t.Fatalf("RequestCount = %d, want 2", got.RequestCount)
	}
	if got.ErrorCount != 1 {
		t.Fatalf("ErrorCount = %d, want 1", got.ErrorCount)
	}
	if got.AverageResponseTimeMs != 20 {
		t.Fatalf("AverageResponseTimeMs = %v, want 20", got.AverageResponseTimeMs)
	}
	if got.ActiveConnections != 0 {
		t.Fatalf("ActiveConnections = %d, want 0 (every BeginRequest was matched by EndRequest)", got.ActiveConnections)
	}
}

// Requirement: EH-F-11
func TestRequestCounters_SnapshotWithNoRequestsHasZeroAverage(t *testing.T) {
	c := &RequestCounters{}

	got := c.Snapshot()

	if got.RequestCount != 0 || got.AverageResponseTimeMs != 0 {
		t.Fatalf("Snapshot on an empty RequestCounters = %+v, want all zero", got)
	}
}

// Requirement: EH-F-10
func TestRequestCounters_ActiveConnectionsTracksInFlightRequests(t *testing.T) {
	c := &RequestCounters{}

	c.BeginRequest()
	c.BeginRequest()

	if got := c.Snapshot().ActiveConnections; got != 2 {
		t.Fatalf("ActiveConnections mid-flight = %d, want 2", got)
	}

	c.EndRequest(time.Millisecond, false)

	if got := c.Snapshot().ActiveConnections; got != 1 {
		t.Fatalf("ActiveConnections after one EndRequest = %d, want 1", got)
	}
}

// Requirement: DV-F-16
// Requirement: DV-F-17
func TestRequestCounters_TrackRecordsSuccessfulRequest(t *testing.T) {
	c := &RequestCounters{}

	isError := false
	end := c.Track(&isError)
	if got := c.Snapshot().ActiveConnections; got != 1 {
		t.Fatalf("ActiveConnections while Track's returned func is still pending = %d, want 1", got)
	}
	end()

	got := c.Snapshot()
	if got.RequestCount != 1 {
		t.Fatalf("RequestCount = %d, want 1", got.RequestCount)
	}
	if got.ErrorCount != 0 {
		t.Fatalf("ErrorCount = %d, want 0", got.ErrorCount)
	}
	if got.ActiveConnections != 0 {
		t.Fatalf("ActiveConnections = %d, want 0", got.ActiveConnections)
	}
}

// Requirement: DV-F-16
// Requirement: DV-F-17
func TestRequestCounters_TrackReadsIsErrorAtDeferTime(t *testing.T) {
	c := &RequestCounters{}

	// isError is flipped to true AFTER Track is called but BEFORE the
	// returned func runs — mirroring how a handler sets isError partway
	// through its own body, then relies on a deferred call to read the
	// final value. Track must read *isError at call-time of the returned
	// func, not capture its value at Track's own call time.
	isError := false
	end := c.Track(&isError)
	isError = true
	end()

	if got := c.Snapshot().ErrorCount; got != 1 {
		t.Fatalf("ErrorCount = %d, want 1 (Track must read *isError at defer-time)", got)
	}
}
