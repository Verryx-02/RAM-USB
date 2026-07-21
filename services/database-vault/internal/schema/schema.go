// Package schema applies Database-Vault's SQL migrations
// (services/database-vault/migrations) to a real Postgres database. It is
// the single place that constructs a golang-migrate instance, called both
// by cmd/database-vault/main.go at process startup (Up() only, never
// Down()) and by internal/storage/postgres_test.go's real-Postgres test
// setup (which also needs Down() for its own cleanup, via the *migrate.Migrate
// New returns).
//
// This package backs no DV-F-* requirement directly: applying migrations
// automatically at startup is internal wiring, not itself a specified
// behavior. It exists to guarantee a fresh Postgres instance has a working
// users table (DV-F-08's schema) before the server starts accepting
// connections, and to fail startup (RD-04, fail-secure) rather than serve
// requests against a schema that might not match what the code expects.
package schema

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepgx5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file" // registers the "file://" migration-source driver New's migrationsDir path needs

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver sql.Open above needs
)

// New builds a *migrate.Migrate pointed at the migrations in
// migrationsDir (a filesystem path, not a "file://" URL) and the Postgres
// database at databaseURL. Callers apply pending migrations via Apply; test
// callers may additionally call the returned instance's Down() themselves
// for cleanup (production code never does).
func New(databaseURL, migrationsDir string) (*migrate.Migrate, error) {
	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("schema: sql.Open: %w", err)
	}

	driver, err := migratepgx5.WithInstance(sqlDB, &migratepgx5.Config{})
	if err != nil {
		return nil, fmt.Errorf("schema: migratepgx5.WithInstance: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://"+migrationsDir, "pgx5", driver)
	if err != nil {
		return nil, fmt.Errorf("schema: migrate.NewWithDatabaseInstance: %w", err)
	}

	return m, nil
}

// Apply runs every pending migration, bringing the schema up to date.
// migrate.ErrNoChange (schema already current) is treated as success, not
// an error. Apply only ever calls m.Up() — Down() is test-cleanup-only and
// must never run against a real database; callers that need Down() (only
// internal/storage/postgres_test.go, as of this package's introduction)
// call it directly on the *migrate.Migrate New returned.
func Apply(m *migrate.Migrate) error {
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("schema: apply migrations: %w", err)
	}
	return nil
}
