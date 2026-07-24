package main

import (
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

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

// Requirement: RD-04
func TestRequireEnv_FailsClosedOnMissingOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		set   bool
		value string
	}{
		{name: "unset", set: false},
		{name: "empty", set: true, value: ""},
	}

	const envVar = "RAM_USB_CERTIFICATE_AUTHORITY_METRICS_TEST_ENV"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(envVar, tt.value)
			}

			if _, err := requireEnv(envVar); err == nil {
				t.Fatalf("requireEnv(%q) err = nil, want non-nil", envVar)
			}
		})
	}
}

// Requirement: RD-04
func TestRequireEnv_ReturnsSetValue(t *testing.T) {
	const envVar = "RAM_USB_CERTIFICATE_AUTHORITY_METRICS_TEST_ENV"
	t.Setenv(envVar, "a-value")

	got, err := requireEnv(envVar)
	if err != nil {
		t.Fatalf("requireEnv(%q) unexpected err = %v", envVar, err)
	}
	if got != "a-value" {
		t.Fatalf("requireEnv(%q) = %q, want %q", envVar, got, "a-value")
	}
}
