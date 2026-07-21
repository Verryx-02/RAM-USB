package main

import (
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// Requirement: SS-F-07
//
// This process's own metrics wiring (serviceName, passed to
// metrics.PublishOnce in run()) must resolve to the SRS's literal
// `metrics/Security-Switch` topic - the generic mechanism itself
// (TopicFor/BuildPayload/PublishOnce) is proved once in pkg/metrics, this
// test only proves Security-Switch supplied the right identity to it.
func TestServiceName_MatchesSRSMetricsTopic(t *testing.T) {
	const wantServiceName = "Security-Switch"
	const wantTopic = "metrics/Security-Switch"

	if serviceName != wantServiceName {
		t.Fatalf("serviceName = %q, want %q", serviceName, wantServiceName)
	}
	if got := metrics.TopicFor(serviceName); got != wantTopic {
		t.Errorf("metrics.TopicFor(serviceName) = %q, want %q", got, wantTopic)
	}
}
