package main

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// Requirement: CA-F-03
//
// Publishing to `metrics/Certificate-Authority` is this process's only job,
// so a missing broker URL must be a startup error (RD-04, fail-secure), not
// a silently degraded process that tails the log and publishes nothing.
func TestBuildMetricsClient_FailsWhenBrokerURLIsUnset(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
	}{
		{name: "unset", set: false},
		{name: "empty", value: "", set: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(envMQTTBrokerURL, tt.value)
			} else {
				t.Setenv(envMQTTBrokerURL, "placeholder")
				if err := os.Unsetenv(envMQTTBrokerURL); err != nil {
					t.Fatalf("Unsetenv: %v", err)
				}
			}

			client, err := buildMetricsClient(&tls.Config{MinVersion: tls.VersionTLS13})
			if err == nil {
				t.Fatalf("buildMetricsClient() error = nil, want a startup error")
			}
			if client != nil {
				t.Errorf("buildMetricsClient() client = %v, want nil", client)
			}
		})
	}
}

// Requirement: CA-F-03
//
// This process's own metrics wiring (serviceName, passed to
// metrics.PublishOnce in run()) must resolve to the SRS's literal
// `metrics/Certificate-Authority` topic - the generic mechanism itself
// (TopicFor/BuildPayload/PublishOnce) is proved once in pkg/metrics, this
// test only proves this process supplied the right identity to it.
func TestServiceName_MatchesSRSMetricsTopic(t *testing.T) {
	const wantServiceName = "Certificate-Authority"
	const wantTopic = "metrics/Certificate-Authority"

	if serviceName != wantServiceName {
		t.Fatalf("serviceName = %q, want %q", serviceName, wantServiceName)
	}
	if got := metrics.TopicFor(serviceName); got != wantTopic {
		t.Errorf("metrics.TopicFor(serviceName) = %q, want %q", got, wantTopic)
	}
}
