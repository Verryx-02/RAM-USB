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

// Requirement: RNF-SEC-02
// Requirement: RNF-SEC-03
func TestSanitize(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text is unchanged",
			input: "malformed request body",
			want:  "malformed request body",
		},
		{
			name:  "empty string is unchanged",
			input: "",
			want:  "",
		},
		{
			name:  "embedded newline is neutralized",
			input: "unknown field \"x\"\nlevel=ERROR msg=\"forged log line\"",
			want:  "unknown field \"x\" level=ERROR msg=\"forged log line\"",
		},
		{
			name:  "embedded carriage return is neutralized",
			input: "value\rlevel=ERROR msg=\"forged\"",
			want:  "value level=ERROR msg=\"forged\"",
		},
		{
			name:  "embedded tab and NUL are neutralized",
			input: "a\tb\x00c",
			want:  "a b c",
		},
		{
			name:  "CRLF pair collapses to two spaces",
			input: "a\r\nb",
			want:  "a  b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			if got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Requirement: RNF-SEC-02
// Requirement: RNF-SEC-03
func TestSanitize_NeverProducesAdditionalLogLine(t *testing.T) {
	const malicious = "bad field\nlevel=ERROR msg=\"attacker forged this line\" user=admin"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Warn("request rejected", "error", Sanitize(malicious))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("log output produced %d lines, want 1: %q", len(lines), buf.String())
	}
	if strings.Contains(buf.String(), "\n") && strings.Count(buf.String(), "\n") > 1 {
		t.Errorf("log output contains an embedded newline: %q", buf.String())
	}
}
