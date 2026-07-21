// Package schema applies Metrics-Collector's SQL migrations
// (services/metrics-collector/migrations) to a real TimescaleDB database.
// It is the single place that constructs a golang-migrate instance,
// called both by cmd/metrics-collector/main.go at process startup (Up()
// only, never Down()) and by internal/store/store_test.go's real-Postgres
// test setup (which also needs Down() for its own cleanup).
//
// Identical in shape to Database-Vault's internal/schema (same New/Apply
// wrapper around golang-migrate + pgx/v5/stdlib) - not extracted to a
// shared pkg/ package, since golang-migrate's own
// migrate.NewWithDatabaseInstance already IS the one-line shared
// abstraction; duplicating this ~20-line wrapper per service keeps each
// service's cmd/main.go call site self-contained and avoids a pkg/schema
// package whose only two callers would still each need their own
// migrationsDir default and env var name.
//
// This package backs MT-F-03 indirectly: applying migrations
// automatically at startup is internal wiring (guaranteeing the "metrics"
// hypertable, its retention policy, and its columnstore compression
// policy all exist before this process accepts any MQTT message), not
// itself a specified behavior. See third-party/timescaledb/init.sql's own
// doc comment for why CREATE EXTENSION timescaledb runs there instead of
// in a migration here.
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
// migrationsDir (a filesystem path, not a "file://" URL) and the
// TimescaleDB/Postgres database at databaseURL. Callers apply pending
// migrations via Apply; test callers may additionally call the returned
// instance's Down() themselves for cleanup (production code never does).
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
// internal/store/store_test.go, as of this package's introduction) call
// it directly on the *migrate.Migrate New returned.
func Apply(m *migrate.Migrate) error {
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("schema: apply migrations: %w", err)
	}
	return nil
}
