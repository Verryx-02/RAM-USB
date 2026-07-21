package metrics_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// testServiceName stands in for any real service's identity (e.g.
// Entry-Hub's "Entry-Hub", EH-F-10's literal SRS example) - this
// package's tests prove the shared mechanism works for any service name,
// not one particular service's requirement.
const testServiceName = "Entry-Hub"

// Requirement: EH-F-11
// Requirement: SS-F-08
// Requirement: DV-F-17
// Requirement: ST-F-13
// Requirement: NM-F-18
// Requirement: CA-F-03
func TestBuildPayload_NeverContainsPersonalData(t *testing.T) {
	counters := metrics.Counters{
		RequestCount:          120,
		ErrorCount:            3,
		AverageResponseTimeMs: 42.5,
		ActiveConnections:     7,
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

	raw, err := metrics.BuildPayload(testServiceName, counters, now)
	if err != nil {
		t.Fatalf("BuildPayload() error = %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	// The payload's field set is exactly this, and only this - every
	// field is a count, an average, or a timestamp. Any additional field
	// (email, username, ip, ssh_public_key, ...) would be a violation of
	// every service's paired "aggregated statistics only" requirement.
	wantFields := map[string]bool{
		"service":                  true,
		"timestamp":                true,
		"request_count":            true,
		"error_count":              true,
		"average_response_time_ms": true,
		"active_connections":       true,
	}

	for name := range fields {
		if !wantFields[name] {
			t.Errorf("payload has unexpected field %q, want only aggregated-statistics fields", name)
		}
	}
	for name := range wantFields {
		if _, ok := fields[name]; !ok {
			t.Errorf("payload is missing expected field %q", name)
		}
	}

	// Defence in depth: the raw JSON text itself must not contain any of
	// the shapes personal data could take, in case a future field is
	// ever added to Payload without updating this test's field list.
	forbidden := []string{"email", "@", "username", "ssh", "password", "ip_address"}
	lower := strings.ToLower(string(raw))
	for _, substr := range forbidden {
		if strings.Contains(lower, substr) {
			t.Errorf("payload JSON %q contains forbidden substring %q", string(raw), substr)
		}
	}
}

// Requirement: EH-F-10
// Requirement: SS-F-07
// Requirement: DV-F-16
// Requirement: ST-F-12
// Requirement: NM-F-17
// Requirement: CA-F-03
func TestBuildPayload_ServiceFieldMatchesTopic(t *testing.T) {
	raw, err := metrics.BuildPayload(testServiceName, metrics.Counters{}, time.Now())
	if err != nil {
		t.Fatalf("BuildPayload() error = %v", err)
	}

	var payload metrics.Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	if payload.Service != testServiceName {
		t.Errorf("payload.Service = %q, want %q", payload.Service, testServiceName)
	}

	wantTopic := "metrics/" + payload.Service
	if got := metrics.TopicFor(testServiceName); got != wantTopic {
		t.Errorf("metrics.TopicFor(%q) = %q, want %q (must match Payload.Service for MT-F-02)", testServiceName, got, wantTopic)
	}
}

// Requirement: MT-F-04
func TestBuildPayload_CountersRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		counters metrics.Counters
	}{
		{
			name:     "zero counters",
			counters: metrics.Counters{},
		},
		{
			name: "nonzero counters",
			counters: metrics.Counters{
				RequestCount:          1000,
				ErrorCount:            10,
				AverageResponseTimeMs: 12.34,
				ActiveConnections:     55,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := metrics.BuildPayload(testServiceName, tt.counters, time.Now())
			if err != nil {
				t.Fatalf("BuildPayload() error = %v", err)
			}

			var payload metrics.Payload
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatalf("json.Unmarshal(payload) error = %v", err)
			}

			if payload.RequestCount != tt.counters.RequestCount {
				t.Errorf("RequestCount = %d, want %d", payload.RequestCount, tt.counters.RequestCount)
			}
			if payload.ErrorCount != tt.counters.ErrorCount {
				t.Errorf("ErrorCount = %d, want %d", payload.ErrorCount, tt.counters.ErrorCount)
			}
			if payload.AverageResponseTimeMs != tt.counters.AverageResponseTimeMs {
				t.Errorf("AverageResponseTimeMs = %v, want %v", payload.AverageResponseTimeMs, tt.counters.AverageResponseTimeMs)
			}
			if payload.ActiveConnections != tt.counters.ActiveConnections {
				t.Errorf("ActiveConnections = %d, want %d", payload.ActiveConnections, tt.counters.ActiveConnections)
			}
		})
	}
}

// Requirement: MT-F-02
func TestTopicFor_MatchesLiteralPerServicePattern(t *testing.T) {
	tests := []struct {
		serviceName string
		wantTopic   string
	}{
		{"Entry-Hub", "metrics/Entry-Hub"},
		{"Security-Switch", "metrics/Security-Switch"},
		{"Database-Vault", "metrics/Database-Vault"},
		{"Storage-Service", "metrics/Storage-Service"},
		{"Network-Manager", "metrics/Network-Manager"},
		{"Certificate-Authority", "metrics/Certificate-Authority"},
	}

	for _, tt := range tests {
		t.Run(tt.serviceName, func(t *testing.T) {
			if got := metrics.TopicFor(tt.serviceName); got != tt.wantTopic {
				t.Errorf("TopicFor(%q) = %q, want %q", tt.serviceName, got, tt.wantTopic)
			}
		})
	}
}
