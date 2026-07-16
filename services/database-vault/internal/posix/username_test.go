package posix_test

import (
	"regexp"
	"testing"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/posix"
)

// usernamePattern matches DV-F-09/ST-F-06's exact format: "user" followed
// by six lowercase base-36 characters, nothing more.
var usernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// Requirement: DV-F-09
func TestGenerateUsername_Format(t *testing.T) {
	for i := 0; i < 1000; i++ {
		got, err := posix.GenerateUsername()
		if err != nil {
			t.Fatalf("GenerateUsername() error = %v", err)
		}
		if !usernamePattern.MatchString(got) {
			t.Fatalf("GenerateUsername() = %q, want match of %s", got, usernamePattern.String())
		}
	}
}

// Requirement: DV-F-09
func TestGenerateUsername_Randomness(t *testing.T) {
	const attempts = 1000

	seen := make(map[string]struct{}, attempts)
	for i := 0; i < attempts; i++ {
		got, err := posix.GenerateUsername()
		if err != nil {
			t.Fatalf("GenerateUsername() error = %v", err)
		}
		seen[got] = struct{}{}
	}

	// A cryptographically random 6-character base-36 suffix has 36^6 (over
	// 2 billion) possible values; among 1000 draws, seeing a duplicate at
	// all would be a red flag that the generator isn't actually random,
	// not proof of a collision. This checks for gross non-randomness (e.g.
	// a constant or a narrow range), not a formal statistical test.
	if len(seen) < attempts/2 {
		t.Fatalf("GenerateUsername() produced only %d distinct values out of %d attempts, want closer to %d", len(seen), attempts, attempts)
	}
}
