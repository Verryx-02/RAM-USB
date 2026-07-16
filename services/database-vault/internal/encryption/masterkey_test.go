package encryption

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// Requirement: DV-F-05
func TestLoadMasterKey(t *testing.T) {
	valid32 := strings.Repeat("k", 32)
	tooShort := strings.Repeat("k", 16)
	tooLong := strings.Repeat("k", 48)

	tests := []struct {
		name    string
		setEnv  bool
		envVal  string
		wantErr bool
	}{
		{
			name:    "valid 32-byte key is accepted",
			setEnv:  true,
			envVal:  base64.StdEncoding.EncodeToString([]byte(valid32)),
			wantErr: false,
		},
		{
			name:    "missing env var is rejected",
			setEnv:  false,
			wantErr: true,
		},
		{
			name:    "too-short decoded key is rejected",
			setEnv:  true,
			envVal:  base64.StdEncoding.EncodeToString([]byte(tooShort)),
			wantErr: true,
		},
		{
			name:    "too-long decoded key is rejected",
			setEnv:  true,
			envVal:  base64.StdEncoding.EncodeToString([]byte(tooLong)),
			wantErr: true,
		},
		{
			name:    "invalid base64 is rejected",
			setEnv:  true,
			envVal:  "not-valid-base64!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(masterKeyEnvVar, tt.envVal)
			} else {
				// t.Setenv only sets a value, it cannot unset one; use
				// os.Unsetenv directly with a manual Cleanup restore so
				// this case truly observes a missing env var, not merely
				// an empty one, regardless of what the outer environment
				// (or an earlier subtest) left behind.
				prev, wasSet := os.LookupEnv(masterKeyEnvVar)
				if err := os.Unsetenv(masterKeyEnvVar); err != nil {
					t.Fatalf("os.Unsetenv(%q) error = %v", masterKeyEnvVar, err)
				}
				t.Cleanup(func() {
					if wasSet {
						if err := os.Setenv(masterKeyEnvVar, prev); err != nil {
							t.Fatalf("os.Setenv(%q) restore error = %v", masterKeyEnvVar, err)
						}
					}
				})
			}

			key, err := LoadMasterKey()

			if tt.wantErr {
				if err == nil {
					t.Fatalf("LoadMasterKey() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadMasterKey() unexpected error = %v", err)
			}
			if len(key) != masterKeySize {
				t.Fatalf("LoadMasterKey() key length = %d, want %d", len(key), masterKeySize)
			}
		})
	}
}
