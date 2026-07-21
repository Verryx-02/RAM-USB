-- MT-F-03: "Metrics must be stored as a TimescaleDB hypertable, with
-- automatic 30-day retention and compression after 7 days."
--
-- Column shapes match pkg/metrics.Payload exactly (its own doc comment:
-- "the exact JSON shape published to a service's metrics topic every
-- minute" - EH-F-10, SS-F-07, DV-F-16, ST-F-12, NM-F-17, CA-F-03):
--
--   Payload.Service               -> service (TEXT)
--   Payload.Timestamp (RFC3339)   -> time (TIMESTAMPTZ, parsed by
--                                    internal/store.Store.Insert before
--                                    this INSERT's $1 argument - stored as
--                                    a real timestamp type, not the
--                                    original string, so TimescaleDB's
--                                    time-range partitioning/retention/
--                                    compression policies below can act on
--                                    it directly)
--   Payload.RequestCount          -> request_count (BIGINT)
--   Payload.ErrorCount            -> error_count (BIGINT)
--   Payload.AverageResponseTimeMs -> average_response_time_ms (DOUBLE PRECISION)
--   Payload.ActiveConnections     -> active_connections (BIGINT)
--
-- No primary key: a metrics row has no natural unique identity, and
-- TimescaleDB hypertables do not require one - see
-- services/metrics-collector/internal/schema's doc comment for the
-- CREATE EXTENSION / migration split rationale (verified live against a
-- real timescale/timescaledb:2.23.0-pg18 container this session: the base
-- image's own /docker-entrypoint-initdb.d/000_install_timescaledb.sh
-- already creates the "timescaledb" extension in every POSTGRES_DB
-- automatically, but third-party/timescaledb/init.sql still declares
-- CREATE EXTENSION IF NOT EXISTS timescaledb explicitly as a defensive,
-- idempotent guarantee this migration does not have to depend on that
-- image-internal behavior persisting unannounced across image versions).
--
-- Every statement below ran successfully, in this exact multi-statement
-- form, in one single database/sql ExecContext call over the "pgx" stdlib
-- driver (golang-migrate's pgx/v5 driver, per its own Run/runStatement,
-- sends an entire migration file as one Exec call unless
-- MultiStatementEnabled is set - not the case here) against a real
-- timescale/timescaledb:2.23.0-pg18 container this session, confirming
-- Postgres's simple-query-protocol implicit-transaction semantics permit
-- create_hypertable/add_retention_policy/CALL add_columnstore_policy to
-- run back-to-back this way.
CREATE TABLE metrics (
    time                      TIMESTAMPTZ NOT NULL,
    service                   TEXT NOT NULL,
    request_count             BIGINT NOT NULL,
    error_count               BIGINT NOT NULL,
    average_response_time_ms  DOUBLE PRECISION NOT NULL,
    active_connections        BIGINT NOT NULL
);

-- by_range('time') is the generalized dimension-builder form TimescaleDB
-- 2.18+ documents as current/preferred over the older single-column-name
-- create_hypertable('metrics', 'time') form (still supported, not used
-- here).
SELECT create_hypertable('metrics', by_range('time'));

-- MT-F-03's "automatic 30-day retention": a background job drops any chunk
-- entirely older than 30 days.
SELECT add_retention_policy('metrics', drop_after => INTERVAL '30 days');

-- MT-F-03's "compression after 7 days". add_compression_policy() is
-- deprecated as of TimescaleDB 2.18 in favor of columnstore: first enable
-- the columnstore storage format on this hypertable (segmentby groups
-- rows likely to be queried together per service; orderby keeps each
-- segment time-ordered, matching how a dashboard query - MT-F-04 - reads
-- this table), then schedule the background job that actually migrates
-- 7-day-old chunks into it. add_columnstore_policy is a stored PROCEDURE
-- (invoked with CALL, not SELECT) - unlike create_hypertable/
-- add_retention_policy above, which are functions.
ALTER TABLE metrics SET (
    timescaledb.enable_columnstore,
    timescaledb.segmentby = 'service',
    timescaledb.orderby = 'time DESC'
);
CALL add_columnstore_policy('metrics', after => INTERVAL '7 days');
