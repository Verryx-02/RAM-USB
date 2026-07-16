package httpapi

import (
	"testing"
	"time"
)

// Requirement: SS-F-07
// Requirement: SS-F-08
func TestCounters_SnapshotReflectsRecordedRequests(t *testing.T) {
	c := &Counters{}

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

// Requirement: SS-F-08
func TestCounters_SnapshotWithNoRequestsHasZeroAverage(t *testing.T) {
	c := &Counters{}

	got := c.Snapshot()

	if got.RequestCount != 0 || got.AverageResponseTimeMs != 0 {
		t.Fatalf("Snapshot on an empty Counters = %+v, want all zero", got)
	}
}

// Requirement: SS-F-07
func TestCounters_ActiveConnectionsTracksInFlightRequests(t *testing.T) {
	c := &Counters{}

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
