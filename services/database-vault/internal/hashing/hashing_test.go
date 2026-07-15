package hashing

import (
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/logging"
)

// Requirement: DV-F-03
func TestHashEmail(t *testing.T) {
	tests := []struct {
		name  string
		email logging.Redacted
		want  string
	}{
		// Expected values are the standard SHA-256 hex digest of the
		// lowercase email string, independently verified with `shasum -a 256`.
		{
			name:  "known vector",
			email: logging.Redacted("user@example.com"),
			want:  "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514",
		},
		{
			name:  "empty string",
			email: logging.Redacted(""),
			want:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashEmail(tt.email)
			if got != tt.want {
				t.Errorf("HashEmail(%q) = %q, want %q", tt.email, got, tt.want)
			}
		})
	}
}

// Requirement: DV-F-03
func TestHashEmail_Deterministic(t *testing.T) {
	const email = logging.Redacted("repeat@example.com")

	first := HashEmail(email)
	second := HashEmail(email)

	if first != second {
		t.Errorf("HashEmail is not deterministic: %q != %q", first, second)
	}
}

// Requirement: DV-F-03
func TestHashEmail_DifferentInputsDifferentHashes(t *testing.T) {
	a := HashEmail(logging.Redacted("alice@example.com"))
	b := HashEmail(logging.Redacted("bob@example.com"))

	if a == b {
		t.Errorf("HashEmail produced the same hash for different emails: %q", a)
	}
}

// Requirement: DV-F-03
func TestHashEmail_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name string
		a    logging.Redacted
		b    logging.Redacted
	}{
		{
			name: "mixed case vs lowercase",
			a:    logging.Redacted("User@Example.com"),
			b:    logging.Redacted("user@example.com"),
		},
		{
			name: "uppercase vs lowercase",
			a:    logging.Redacted("ALICE@EXAMPLE.COM"),
			b:    logging.Redacted("alice@example.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA := HashEmail(tt.a)
			gotB := HashEmail(tt.b)
			if gotA != gotB {
				t.Errorf("HashEmail(%q) = %q, HashEmail(%q) = %q, want equal hashes", tt.a, gotA, tt.b, gotB)
			}
		})
	}
}

// Requirement: DV-F-03
func TestHashEmail_OutputShape(t *testing.T) {
	got := HashEmail(logging.Redacted("shape@example.com"))

	const wantLen = 64 // 32-byte SHA-256 digest, hex-encoded
	if len(got) != wantLen {
		t.Fatalf("HashEmail output length = %d, want %d", len(got), wantLen)
	}
	for _, r := range got {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Fatalf("HashEmail output %q contains non-hex character %q", got, r)
		}
	}
}
