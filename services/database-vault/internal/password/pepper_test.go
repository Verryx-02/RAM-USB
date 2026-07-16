package password

import (
	"os"
	"testing"
)

// Requirement: DV-F-06
func TestLoadPepper(t *testing.T) {
	tests := []struct {
		name    string
		setEnv  bool
		envVal  string
		wantErr bool
	}{
		{
			name:    "valid pepper is accepted",
			setEnv:  true,
			envVal:  "a-sufficiently-random-pepper-value",
			wantErr: false,
		},
		{
			name:    "missing env var is rejected",
			setEnv:  false,
			wantErr: true,
		},
		{
			name:    "empty env var is rejected",
			setEnv:  true,
			envVal:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(pepperEnvVar, tt.envVal)
			} else {
				// t.Setenv only sets a value, it cannot unset one; use
				// os.Unsetenv directly with a manual Cleanup restore so
				// this case truly observes a missing env var, not merely
				// an empty one, regardless of what the outer environment
				// (or an earlier subtest) left behind.
				prev, wasSet := os.LookupEnv(pepperEnvVar)
				if err := os.Unsetenv(pepperEnvVar); err != nil {
					t.Fatalf("os.Unsetenv(%q) error = %v", pepperEnvVar, err)
				}
				t.Cleanup(func() {
					if wasSet {
						if err := os.Setenv(pepperEnvVar, prev); err != nil {
							t.Fatalf("os.Setenv(%q) restore error = %v", pepperEnvVar, err)
						}
					}
				})
			}

			pepper, err := LoadPepper()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("LoadPepper() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadPepper() unexpected error = %v", err)
			}
			if string(pepper) != tt.envVal {
				t.Fatalf("LoadPepper() = %q, want %q", pepper, tt.envVal)
			}
		})
	}
}
