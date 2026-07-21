package main

import (
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// Requirement: NM-F-17
//
// This process's own metrics wiring (serviceName, passed to
// metrics.PublishOnce in run()) must resolve to the SRS's literal
// `metrics/Network-Manager` topic - the generic mechanism itself
// (TopicFor/BuildPayload/PublishOnce) is proved once in pkg/metrics, this
// test only proves Network-Manager supplied the right identity to it.
func TestServiceName_MatchesSRSMetricsTopic(t *testing.T) {
	const wantServiceName = "Network-Manager"
	const wantTopic = "metrics/Network-Manager"

	if serviceName != wantServiceName {
		t.Fatalf("serviceName = %q, want %q", serviceName, wantServiceName)
	}
	if got := metrics.TopicFor(serviceName); got != wantTopic {
		t.Errorf("metrics.TopicFor(serviceName) = %q, want %q", got, wantTopic)
	}
}
