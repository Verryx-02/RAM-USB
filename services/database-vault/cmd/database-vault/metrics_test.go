package main

import (
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// Requirement: DV-F-16
//
// This process's own metrics wiring (serviceName, passed to
// metrics.PublishOnce in run()) must resolve to the SRS's literal
// `metrics/Database-Vault` topic - the generic mechanism itself
// (TopicFor/BuildPayload/PublishOnce) is proved once in pkg/metrics, this
// test only proves Database-Vault supplied the right identity to it.
func TestServiceName_MatchesSRSMetricsTopic(t *testing.T) {
	const wantServiceName = "Database-Vault"
	const wantTopic = "metrics/Database-Vault"

	if serviceName != wantServiceName {
		t.Fatalf("serviceName = %q, want %q", serviceName, wantServiceName)
	}
	if got := metrics.TopicFor(serviceName); got != wantTopic {
		t.Errorf("metrics.TopicFor(serviceName) = %q, want %q", got, wantTopic)
	}
}
