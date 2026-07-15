package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeRow is a hand-written fake implementing pgx.Row (CONTRIBUTING.md
// §7.5): its Scan either writes a fixed string into dest or returns a fixed
// error, simulating what *pgxpool.Pool.QueryRow's returned pgx.Row would do
// for a matched row, a no-rows result (pgx.ErrNoRows), or a lower-level
// query failure — without a real database connection.
type fakeRow struct {
	value   string
	scanErr error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	dest0, ok := dest[0].(*string)
	if !ok {
		return errors.New("fakeRow: unsupported dest type")
	}
	*dest0 = r.value
	return nil
}

// fakeQuerier is a hand-written fake implementing this package's Querier
// interface, returning a fixed fakeRow regardless of the SQL/args passed —
// GetPasswordHash issues exactly one fixed query, so recording the query
// text/args adds nothing to these test cases the way it does for
// fakeStorage's SaveUser/DeleteUser recording in the registration package.
type fakeQuerier struct {
	row fakeRow
}

func (q fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return q.row
}

// Requirement: DV-F-13
func TestGetPasswordHash(t *testing.T) {
	const wantHash = "$argon2id$v=19$m=47104,t=2,p=1$c2FsdA$aGFzaA"

	tests := []struct {
		name        string
		row         fakeRow
		wantHash    string
		wantErr     error
		wantErrText string
	}{
		{
			name:     "found",
			row:      fakeRow{value: wantHash},
			wantHash: wantHash,
		},
		{
			name:    "not found",
			row:     fakeRow{scanErr: pgx.ErrNoRows},
			wantErr: ErrUserNotFound,
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

			got, err := GetPasswordHash(context.Background(), db, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd")

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
			if got != tt.wantHash {
				t.Fatalf("passwordHash = %q, want %q", got, tt.wantHash)
			}
		})
	}
}
