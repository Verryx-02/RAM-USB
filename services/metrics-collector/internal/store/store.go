// Package store persists one already-validated metrics.Payload as a row
// in TimescaleDB's "metrics" hypertable (MT-F-03), the schema
// services/metrics-collector/migrations/000001_create_metrics_table.up.sql
// creates. It performs no validation of its own — internal/collector's
// Handler.Handle has already discarded any payload whose "service" field
// does not match the topic it arrived on (MT-F-02) before Insert is ever
// called; this package's only job is the INSERT.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
)

// insertMetricsSQL matches the "metrics" table's column shape exactly, as
// documented in
// services/metrics-collector/migrations/000001_create_metrics_table.up.sql.
const insertMetricsSQL = `
INSERT INTO metrics (
	time, service, request_count, error_count,
	average_response_time_ms, active_connections
) VALUES ($1, $2, $3, $4, $5, $6)`

// Querier is the minimal subset of *pgxpool.Pool that Insert needs.
// Depending on this narrow interface, instead of the full pgxpool.Pool
// (which also exposes Query, QueryRow, Begin, Acquire, Ping, Stat, Close —
// none of which Insert calls), lets unit tests substitute a small
// hand-written fake per CONTRIBUTING.md §7.5. Same "narrow interface for
// testability" pattern as Database-Vault's internal/storage.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// PoolQuerier adapts a real *pgxpool.Pool to Querier. A bare *pgxpool.Pool
// already satisfies Querier structurally; this wrapper exists only so
// cmd/metrics-collector/main.go's wiring reads the same way Database-Vault's
// storage.PoolQuerier/PoolBeginner wiring does.
type PoolQuerier struct {
	Pool *pgxpool.Pool
}

// Exec delegates to the wrapped *pgxpool.Pool's own Exec, giving
// PoolQuerier a value (not pointer) receiver that satisfies Querier
// structurally — the method body itself does no work beyond that
// delegation, matching Database-Vault's identically-shaped
// storage.PoolQuerier/PoolBeginner wrappers.
func (p PoolQuerier) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return p.Pool.Exec(ctx, sql, arguments...)
}

// Store inserts an accepted metrics.Payload into TimescaleDB.
type Store struct {
	DB Querier
}

// Insert parses payload.Timestamp (metrics.BuildPayload's RFC3339 format)
// into a real time.Time before storing it, so the "time" column is a
// genuine TIMESTAMPTZ the hypertable's partitioning/retention/compression
// policies (MT-F-03) can act on, not an opaque string.
func (s Store) Insert(ctx context.Context, payload metrics.Payload) error {
	timestamp, err := time.Parse(time.RFC3339, payload.Timestamp)
	if err != nil {
		return fmt.Errorf("store: parse payload timestamp %q: %w", payload.Timestamp, err)
	}

	if _, err := s.DB.Exec(ctx, insertMetricsSQL,
		timestamp,
		payload.Service,
		payload.RequestCount,
		payload.ErrorCount,
		payload.AverageResponseTimeMs,
		payload.ActiveConnections,
	); err != nil {
		return fmt.Errorf("store: insert metrics row: %w", err)
	}

	return nil
}
