package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Requirement: DV-F-03
func TestRedacted_LogValue(t *testing.T) {
	tests := []struct {
		name  string
		value Redacted
	}{
		{name: "email", value: Redacted("user@example.com")},
		{name: "password", value: Redacted("Str0ng!Pass")},
		{name: "empty", value: Redacted("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.value.LogValue()
			if got.Kind() != slog.KindString {
				t.Fatalf("LogValue() kind = %v, want %v", got.Kind(), slog.KindString)
			}
			if got.String() != "REDACTED" {
				t.Errorf("LogValue() = %q, want %q", got.String(), "REDACTED")
			}
		})
	}
}

// Requirement: DV-F-03
func TestRedacted_NeverAppearsInLogOutput(t *testing.T) {
	const plaintextEmail = "victim@example.com"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("login attempt", slog.Any("email", Redacted(plaintextEmail)))

	output := buf.String()
	if strings.Contains(output, plaintextEmail) {
		t.Errorf("log output contains plaintext email: %q", output)
	}
	if !strings.Contains(output, "REDACTED") {
		t.Errorf("log output missing REDACTED marker: %q", output)
	}
}
