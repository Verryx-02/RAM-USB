package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Verryx-02/RAM-USB/pkg/metrics"
	"github.com/Verryx-02/RAM-USB/services/metrics-collector/internal/schema"
)

// fakeQuerier is a hand-written fake of Querier (CONTRIBUTING.md §7.5).
type fakeQuerier struct {
	execErr   error
	execCalls int
	lastSQL   string
	lastArgs  []any
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	f.execCalls++
	f.lastSQL = sql
	f.lastArgs = arguments
	if f.execErr != nil {
		return pgconn.CommandTag{}, f.execErr
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

// Requirement: MT-F-03
func TestStore_Insert(t *testing.T) {
	validPayload := metrics.Payload{
		Service:               "Entry-Hub",
		Timestamp:             "2026-07-21T12:00:00Z",
		RequestCount:          42,
		ErrorCount:            1,
		AverageResponseTimeMs: 12.5,
		ActiveConnections:     3,
	}

	t.Run("valid payload is inserted with a parsed timestamp", func(t *testing.T) {
		fake := &fakeQuerier{}
		s := Store{DB: fake}

		if err := s.Insert(context.Background(), validPayload); err != nil {
			t.Fatalf("Insert() error = %v, want nil", err)
		}
		if fake.execCalls != 1 {
			t.Fatalf("Exec called %d times, want 1", fake.execCalls)
		}
		wantTime, err := time.Parse(time.RFC3339, validPayload.Timestamp)
		if err != nil {
			t.Fatalf("time.Parse(want): %v", err)
		}
		gotTime, ok := fake.lastArgs[0].(time.Time)
		if !ok {
			t.Fatalf("first argument = %T, want time.Time", fake.lastArgs[0])
		}
		if !gotTime.Equal(wantTime) {
			t.Fatalf("first argument = %v, want %v", gotTime, wantTime)
		}
		if fake.lastArgs[1] != validPayload.Service {
			t.Fatalf("second argument = %v, want %v", fake.lastArgs[1], validPayload.Service)
		}
	})

	t.Run("malformed timestamp is rejected before any Exec call", func(t *testing.T) {
		fake := &fakeQuerier{}
		s := Store{DB: fake}

		payload := validPayload
		payload.Timestamp = "not-a-timestamp"

		err := s.Insert(context.Background(), payload)
		if err == nil {
			t.Fatal("Insert() error = nil, want non-nil")
		}
		if fake.execCalls != 0 {
			t.Fatalf("Exec called %d times, want 0 (timestamp parse must fail first)", fake.execCalls)
		}
	})

	t.Run("Exec failure is propagated", func(t *testing.T) {
		wantErr := errors.New("connection refused")
		fake := &fakeQuerier{execErr: wantErr}
		s := Store{DB: fake}

		err := s.Insert(context.Background(), validPayload)
		if !errors.Is(err, wantErr) {
			t.Fatalf("Insert() error = %v, want wrapping %v", err, wantErr)
		}
	})
}

// databaseURLEnvVar names the environment variable that points this test
// at a real TimescaleDB instance (e.g. the metrics-collector-timescaledb
// service in deployments/compose/metrics-collector-timescaledb.yml). docs/Test_Plan.md §4
// requires unit tests to run with no external dependency and no Docker —
// so, like Database-Vault's own storage/postgres_test.go, this test is
// skipped whenever the variable is unset, instead of being a hard
// dependency of `go test ./...`.
const databaseURLEnvVar = "METRICS_COLLECTOR_TEST_DATABASE_URL"

// Requirement: MT-F-03
func TestStore_Insert_Postgres(t *testing.T) {
	databaseURL := os.Getenv(databaseURLEnvVar)
	if databaseURL == "" {
		t.Skipf("%s not set; skipping the real-TimescaleDB MT-F-03 test (see docs/Test_Plan.md §4: unit tests run with no external dependency, no Docker). Start deployments/compose/metrics-collector-timescaledb.yml's metrics-collector-timescaledb service and set this variable to run it.", databaseURLEnvVar)
	}

	ctx := context.Background()

	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations directory: %v", err)
	}

	m, err := schema.New(databaseURL, migrationsDir)
	if err != nil {
		t.Fatalf("schema.New: %v", err)
	}
	if err := schema.Apply(m); err != nil {
		t.Fatalf("schema.Apply: %v", err)
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

	s := Store{DB: PoolQuerier{Pool: pool}}

	payload := metrics.Payload{
		Service:               "Database-Vault",
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		RequestCount:          10,
		ErrorCount:            0,
		AverageResponseTimeMs: 5.5,
		ActiveConnections:     2,
	}

	if err := s.Insert(ctx, payload); err != nil {
		t.Fatalf("Insert() against real TimescaleDB: %v", err)
	}

	var count int
	row := pool.QueryRow(ctx, "SELECT count(*) FROM metrics WHERE service = $1", payload.Service)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("verify inserted row: %v", err)
	}
	if count != 1 {
		t.Fatalf("metrics rows for service %q = %d, want 1", payload.Service, count)
	}
}
