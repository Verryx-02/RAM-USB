package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Requirement: ST-F-11
func TestGetSSHPublicKeyByPosixUsername(t *testing.T) {
	const wantKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@example.com"

	tests := []struct {
		name        string
		row         fakeRow
		wantKey     string
		wantErr     error
		wantErrText string
	}{
		{
			name:    "found",
			row:     fakeRow{value: wantKey},
			wantKey: wantKey,
		},
		{
			name:    "not found",
			row:     fakeRow{scanErr: pgx.ErrNoRows},
			wantErr: ErrPosixUsernameNotFound,
		},
		{
			name:        "query failure",
			row:         fakeRow{scanErr: errors.New("connection reset")},
			wantErrText: "connection reset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := fakeQuerier{row: tt.row}

			got, err := GetSSHPublicKeyByPosixUsername(context.Background(), db, "user1a2b3c")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want wrapping %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErrText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErrText)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if got != tt.wantKey {
				t.Fatalf("sshPublicKey = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
