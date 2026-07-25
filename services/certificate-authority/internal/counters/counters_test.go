package counters

import "testing"

// Requirement: CA-F-03
func TestCounters_SnapshotReflectsRecordedRequests(t *testing.T) {
	c := &Counters{}

	c.Record(200, 10_000_000) // 10ms
	c.Record(500, 30_000_000) // 30ms, error
	c.Record(404, 20_000_000) // 20ms, error

	got := c.Snapshot()

	if got.RequestCount != 3 {
		t.Fatalf("RequestCount = %d, want 3", got.RequestCount)
	}
	if got.ErrorCount != 2 {
		t.Fatalf("ErrorCount = %d, want 2", got.ErrorCount)
	}
	if got.AverageResponseTimeMs != 20 {
		t.Fatalf("AverageResponseTimeMs = %v, want 20", got.AverageResponseTimeMs)
	}
	if got.ActiveConnections != 0 {
		t.Fatalf("ActiveConnections = %d, want 0 (not applicable to a log-derived sidecar)", got.ActiveConnections)
	}
}

// Requirement: CA-F-03
func TestCounters_SnapshotWithNoRequestsHasZeroAverage(t *testing.T) {
	c := &Counters{}

	got := c.Snapshot()

	if got.RequestCount != 0 || got.ErrorCount != 0 || got.AverageResponseTimeMs != 0 {
		t.Fatalf("Snapshot on an empty Counters = %+v, want all zero", got)
	}
}

// Requirement: CA-F-03
func TestCounters_StatusBelow400IsNotAnError(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantError bool
	}{
		{"200 OK", 200, false},
		{"201 Created", 201, false},
		{"301 redirect", 301, false},
		{"399 boundary", 399, false},
		{"400 boundary", 400, true},
		{"404 not found", 404, true},
		{"500 server error", 500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Counters{}
			c.Record(tt.status, 1_000_000)

			got := c.Snapshot()
			wantErrorCount := int64(0)
			if tt.wantError {
				wantErrorCount = 1
			}
			if got.ErrorCount != wantErrorCount {
				t.Fatalf("status %d: ErrorCount = %d, want %d", tt.status, got.ErrorCount, wantErrorCount)
			}
		})
	}
}
