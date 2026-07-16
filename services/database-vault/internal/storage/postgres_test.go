package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	migratepgx5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/encryption"
)

// databaseURLEnvVar names the environment variable that points this test at
// a real Postgres instance (e.g. the database-vault-postgres service in
// deployments/docker-compose.dev.yml). docs/Test_Plan.md §4 requires unit
// tests to run with no external dependency and no Docker, so — unlike
// every other DV-F-08 test in this package, which uses a hand-written fake
// — this test is skipped whenever the variable is unset, instead of being
// a hard dependency of `go test ./...`.
const databaseURLEnvVar = "DATABASE_VAULT_TEST_DATABASE_URL"

// Requirement: DV-F-08
func TestSaveUser_Postgres(t *testing.T) {
	databaseURL := os.Getenv(databaseURLEnvVar)
	if databaseURL == "" {
		t.Skipf("%s not set; skipping the real-Postgres DV-F-08 test (see docs/Test_Plan.md §4: unit tests run with no external dependency, no Docker). Start deployments/docker-compose.dev.yml's database-vault-postgres service and set this variable to run it.", databaseURLEnvVar)
	}

	ctx := context.Background()

	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations directory: %v", err)
	}

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	driver, err := migratepgx5.WithInstance(sqlDB, &migratepgx5.Config{})
	if err != nil {
		t.Fatalf("migratepgx5.WithInstance: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+migrationsDir, "pgx5", driver)
	if err != nil {
		t.Fatalf("migrate.NewWithDatabaseInstance: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Errorf("roll back migrations during cleanup: %v", err)
		}
	})

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	db := PoolBeginner{Pool: pool}

	record := UserRecord{ //nolint:gosec // fixture data, not a real password hash
		EmailHash: "postgres0123456789abcdef0123456789abcdef0123456789abcdef012345",
		EmailEncrypted: encryption.EncryptedEmail{
			Salt:       []byte("0123456789abcdef"),
			Nonce:      []byte("012345678901"),
			Ciphertext: []byte("ciphertext-bytes"),
		},
		PasswordHash:  "$argon2id$v=19$m=47104,t=2,p=1$c2FsdA$aGFzaA",
		SSHPublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...postgres-test",
		PosixUsername: "user9x8y7z",
	}

	if err := SaveUser(ctx, db, record); err != nil {
		t.Fatalf("SaveUser() first insert error = %v, want nil", err)
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE email_hash = $1", record.EmailHash).Scan(&count); err != nil {
		t.Fatalf("read back row count: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count after first insert = %d, want 1", count)
	}

	// Atomicity/uniqueness: a second insert with the same email_hash must
	// fail as a whole (no half-written row) and be distinguishable as a
	// duplicate, not silently overwrite or partially apply.
	err = SaveUser(ctx, db, record)
	if !errors.Is(err, ErrDuplicateUser) {
		t.Fatalf("SaveUser() second insert error = %v, want wrapping ErrDuplicateUser", err)
	}

	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE email_hash = $1", record.EmailHash).Scan(&count); err != nil {
		t.Fatalf("read back row count after rejected duplicate: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count after rejected duplicate = %d, want still 1 (no partial write)", count)
	}
}
