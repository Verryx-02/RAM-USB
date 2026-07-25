package env

import "testing"

// Requirement: RD-04
func TestRequire_FailsClosedOnMissingOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		set   bool
		value string
	}{
		{name: "unset", set: false},
		{name: "empty", set: true, value: ""},
	}

	const envVar = "RAM_USB_PKG_ENV_TEST_ENV"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(envVar, tt.value)
			}

			if _, err := Require(envVar); err == nil {
				t.Fatalf("Require(%q) err = nil, want non-nil", envVar)
			}
		})
	}
}

// Requirement: RD-04
func TestRequire_ReturnsSetValue(t *testing.T) {
	const envVar = "RAM_USB_PKG_ENV_TEST_ENV"
	t.Setenv(envVar, "a-value")

	got, err := Require(envVar)
	if err != nil {
		t.Fatalf("Require(%q) unexpected err = %v", envVar, err)
	}
	if got != "a-value" {
		t.Fatalf("Require(%q) = %q, want %q", envVar, got, "a-value")
	}
}
