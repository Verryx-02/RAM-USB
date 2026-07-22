package schema

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// databaseURLEnvVar names the environment variable that points this test at
// a real Postgres instance (e.g. the database-vault-postgres service in
// deployments/compose/postgres.yml). docs/Test_Plan.md §4 requires unit
// tests to run with no external dependency and no Docker, so this test is
// skipped whenever the variable is unset, instead of being a hard
// dependency of `go test ./...` — same convention as
// internal/storage/postgres_test.go's TestSaveUser_Postgres.
const databaseURLEnvVar = "DATABASE_VAULT_TEST_DATABASE_URL"

// TestNewAndApply_CreatesUsersTableFromEmptyDatabase verifies that, starting
// from a genuinely empty Postgres database (no users table, no
// schema_migrations bookkeeping table), calling New followed by Apply
// creates the users table and its idx_users_posix_username unique index.
// This is a plain descriptive test, not tagged "// Requirement: <ID>":
// applying migrations at startup is an internal wiring chore with no
// dedicated DV-F-* requirement ID, per this task's explicit scope.
func TestNewAndApply_CreatesUsersTableFromEmptyDatabase(t *testing.T) {
	databaseURL := os.Getenv(databaseURLEnvVar)
	if databaseURL == "" {
		t.Skipf("%s not set; skipping the real-Postgres schema test (see docs/Test_Plan.md §4: unit tests run with no external dependency, no Docker). Start deployments/compose/postgres.yml's database-vault-postgres service and set this variable to run it.", databaseURLEnvVar)
	}

	ctx := context.Background()

	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations directory: %v", err)
	}

	// Start from a genuinely empty database: drop both the table this
	// migration creates and golang-migrate's own bookkeeping table, so
	// this test does not depend on whatever state a previous test run
	// left behind.
	setupDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := setupDB.ExecContext(ctx, "DROP TABLE IF EXISTS users"); err != nil {
		t.Fatalf("drop users table: %v", err)
	}
	if _, err := setupDB.ExecContext(ctx, "DROP TABLE IF EXISTS schema_migrations"); err != nil {
		t.Fatalf("drop schema_migrations table: %v", err)
	}
	if err := setupDB.Close(); err != nil {
		t.Fatalf("close setup connection: %v", err)
	}

	m, err := New(databaseURL, migrationsDir)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		// Down() is test-cleanup-only; production code (New/Apply as
		// called from main.go) never calls it.
		if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Errorf("roll back migrations during cleanup: %v", err)
		}
	})

	if err := Apply(m); err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	var tableExists bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')",
	).Scan(&tableExists); err != nil {
		t.Fatalf("check users table existence: %v", err)
	}
	if !tableExists {
		t.Fatalf("users table does not exist after Apply()")
	}

	var indexExists bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT FROM pg_indexes WHERE indexname = 'idx_users_posix_username')",
	).Scan(&indexExists); err != nil {
		t.Fatalf("check idx_users_posix_username index existence: %v", err)
	}
	if !indexExists {
		t.Fatalf("idx_users_posix_username index does not exist after Apply()")
	}
}
