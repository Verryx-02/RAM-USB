#!/bin/bash

echo "============================================"
echo "Metrics-Collector TimescaleDB Setup"
echo "============================================"
echo ""

# Check if PostgreSQL is running
if ! pg_isready >/dev/null 2>&1; then
    echo "Error: PostgreSQL is not running"
    echo "Start with: brew services start postgresql (macOS)"
    echo "           sudo systemctl start postgresql (Linux)"
    exit 1
fi

echo "PostgreSQL is running"

# Step 1: Install TimescaleDB extension if not installed
echo ""
echo "Step 1: Checking TimescaleDB installation..."

# Check if TimescaleDB is available
if ! psql -c "SELECT 1 FROM pg_available_extensions WHERE name='timescaledb'" postgres | grep -q 1; then
    echo "TimescaleDB extension not found!"
    echo ""
    echo "To install TimescaleDB:"
    echo "  macOS:  brew install timescaledb"
    echo "  Ubuntu: sudo apt install postgresql-14-timescaledb"
    echo "  Then run: timescaledb-tune --quiet --yes"
    echo ""
    echo "After installation, restart PostgreSQL and run this script again."
    exit 1
fi

echo "TimescaleDB extension is available"

# Step 2: Create metrics database
echo ""
echo "Step 2: Creating metrics database..."

# Create database if not exists
createdb metrics_db 2>/dev/null || echo "   Database 'metrics_db' may already exist"

# Step 3: Create metrics user
echo ""
echo "Step 3: Creating metrics user..."

psql postgres << 'EOF'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'metrics_user') THEN
        CREATE USER metrics_user WITH ENCRYPTED PASSWORD 'metrics_secure_2024';
        RAISE NOTICE 'User metrics_user created';
    ELSE
        RAISE NOTICE 'User metrics_user already exists';
    END IF;
END
$$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE metrics_db TO metrics_user;
EOF

# Step 4: Enable TimescaleDB extension
echo ""
echo "Step 4: Enabling TimescaleDB extension..."

psql metrics_db << 'EOF'
-- Enable TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Grant schema privileges to metrics_user
GRANT ALL ON SCHEMA public TO metrics_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO metrics_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO metrics_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO metrics_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO metrics_user;
EOF

# Step 5: Create tables and hypertables
echo ""
echo "Step 5: Creating metrics tables..."

psql metrics_db << 'EOF'
-- Main metrics table
CREATE TABLE IF NOT EXISTS metrics (
    time         TIMESTAMPTZ NOT NULL,
    service      TEXT NOT NULL,
    metric_name  TEXT NOT NULL,
    metric_type  TEXT NOT NULL DEFAULT 'gauge',
    value        DOUBLE PRECISION NOT NULL,
    labels       JSONB,
    inserted_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Create hypertable for time-series optimization
-- Only create if not already a hypertable
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables 
        WHERE hypertable_name = 'metrics'
    ) THEN
        PERFORM create_hypertable('metrics', 'time', 
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        );
        RAISE NOTICE 'Created hypertable for metrics';
    ELSE
        RAISE NOTICE 'Metrics table is already a hypertable';
    END IF;
END
$$;

-- Create indexes for query performance
CREATE INDEX IF NOT EXISTS idx_metrics_service_time 
    ON metrics (service, time DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_name_time 
    ON metrics (metric_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_labels 
    ON metrics USING gin (labels);

-- Service health tracking table
CREATE TABLE IF NOT EXISTS service_health (
    service       TEXT PRIMARY KEY,
    status        TEXT NOT NULL DEFAULT 'unknown',
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metrics_count BIGINT DEFAULT 0,
    error_rate    DOUBLE PRECISION DEFAULT 0,
    response_time DOUBLE PRECISION DEFAULT 0,
    version       TEXT,
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Validation errors tracking
CREATE TABLE IF NOT EXISTS validation_errors (
    id           SERIAL PRIMARY KEY,
    timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    metric_name  TEXT,
    raw_data     JSONB
);

-- Grant permissions to metrics_user
GRANT ALL ON ALL TABLES IN SCHEMA public TO metrics_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO metrics_user;
EOF

# Step 6: Create continuous aggregates for performance
echo ""
echo "Step 6: Creating continuous aggregates..."

psql metrics_db << 'EOF'
-- Hourly aggregates
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_hourly
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 hour', time) AS hour,
    service,
    metric_name,
    metric_type,
    COUNT(*) as count,
    AVG(value) as avg_value,
    MIN(value) as min_value,
    MAX(value) as max_value,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY value) as median_value,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY value) as p95_value,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY value) as p99_value
FROM metrics
GROUP BY hour, service, metric_name, metric_type
WITH NO DATA;

-- Daily aggregates
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_daily
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 day', time) AS day,
    service,
    metric_name,
    metric_type,
    COUNT(*) as count,
    AVG(value) as avg_value,
    MIN(value) as min_value,
    MAX(value) as max_value,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY value) as median_value,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY value) as p95_value,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY value) as p99_value
FROM metrics
GROUP BY day, service, metric_name, metric_type
WITH NO DATA;

-- Refresh policies for continuous aggregates
SELECT add_continuous_aggregate_policy('metrics_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

SELECT add_continuous_aggregate_policy('metrics_daily',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);
EOF

# Step 7: Create data retention policies
echo ""
echo "Step 7: Setting up data retention policies..."

psql metrics_db << 'EOF'
-- Raw data retention: 30 days
SELECT add_retention_policy('metrics', 
    drop_after => INTERVAL '30 days',
    if_not_exists => TRUE
);

-- Validation errors retention: 7 days
SELECT add_retention_policy('validation_errors',
    drop_after => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- Compression policy for old data (compress after 7 days)
SELECT add_compression_policy('metrics', 
    compress_after => INTERVAL '7 days',
    if_not_exists => TRUE
);
EOF

# Step 8: Create helper functions
echo ""
echo "Step 8: Creating helper functions..."

psql metrics_db << 'EOF'
-- Function to get recent metrics for a service
CREATE OR REPLACE FUNCTION get_recent_metrics(
    p_service TEXT,
    p_interval INTERVAL DEFAULT INTERVAL '5 minutes'
)
RETURNS TABLE(
    time TIMESTAMPTZ,
    metric_name TEXT,
    value DOUBLE PRECISION,
    labels JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT m.time, m.metric_name, m.value, m.labels
    FROM metrics m
    WHERE m.service = p_service
      AND m.time > NOW() - p_interval
    ORDER BY m.time DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to update service health
CREATE OR REPLACE FUNCTION update_service_health(
    p_service TEXT
)
RETURNS VOID AS $$
DECLARE
    v_error_count BIGINT;
    v_total_count BIGINT;
    v_avg_response DOUBLE PRECISION;
BEGIN
    -- Calculate metrics from last 5 minutes
    SELECT 
        COUNT(*) FILTER (WHERE metric_name LIKE '%error%'),
        COUNT(*),
        AVG(value) FILTER (WHERE metric_name LIKE '%duration%' OR metric_name LIKE '%latency%')
    INTO v_error_count, v_total_count, v_avg_response
    FROM metrics
    WHERE service = p_service
      AND time > NOW() - INTERVAL '5 minutes';
    
    -- Update or insert service health
    INSERT INTO service_health (service, status, last_seen, metrics_count, error_rate, response_time)
    VALUES (
        p_service,
        CASE 
            WHEN v_total_count = 0 THEN 'down'
            WHEN v_error_count::DOUBLE PRECISION / NULLIF(v_total_count, 0) > 0.5 THEN 'degraded'
            ELSE 'healthy'
        END,
        NOW(),
        v_total_count,
        COALESCE(v_error_count::DOUBLE PRECISION / NULLIF(v_total_count, 0) * 100, 0),
        COALESCE(v_avg_response, 0)
    )
    ON CONFLICT (service) DO UPDATE
    SET 
        status = EXCLUDED.status,
        last_seen = EXCLUDED.last_seen,
        metrics_count = service_health.metrics_count + EXCLUDED.metrics_count,
        error_rate = EXCLUDED.error_rate,
        response_time = EXCLUDED.response_time,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Grant execute permissions
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO metrics_user;
EOF

# Step 9: Test the setup
echo ""
echo "Step 9: Testing the setup..."

# Test connection as metrics_user
export PGPASSWORD='metrics_secure_2024'
if psql -U metrics_user -d metrics_db -c "SELECT 1" >/dev/null 2>&1; then
    echo "✓ Connection test successful"
else
    echo "✗ Connection test failed"
    exit 1
fi

# Test TimescaleDB functionality
psql -U metrics_user -d metrics_db << 'EOF' >/dev/null 2>&1
-- Insert test metric
INSERT INTO metrics (time, service, metric_name, metric_type, value, labels)
VALUES (NOW(), 'test', 'test_metric', 'gauge', 1.0, '{"test": "true"}');

-- Query test metric
SELECT COUNT(*) FROM metrics WHERE service = 'test';

-- Delete test metric
DELETE FROM metrics WHERE service = 'test';
EOF

if [ $? -eq 0 ]; then
    echo "✓ TimescaleDB functionality test successful"
else
    echo "✗ TimescaleDB functionality test failed"
    exit 1
fi

unset PGPASSWORD

# Step 10: Display connection information
echo ""
echo "============================================"
echo "TimescaleDB Setup Complete!"
echo "============================================"
echo ""
echo "Connection Information:"
echo "  Database: metrics_db"
echo "  User: metrics_user"
echo "  Password: metrics_secure_2024"
echo "  Port: 5432 (default PostgreSQL port)"
echo ""
echo "Environment variables for Metrics-Collector:"
echo ""
echo "export METRICS_DATABASE_URL='postgres://metrics_user:metrics_secure_2024@localhost:5432/metrics_db?sslmode=require'"
echo "export MQTT_BROKER_URL='ssl://YOUR_TAILSCALE_IP:8883'"
echo ""
echo "Features enabled:"
echo "  ✓ Hypertables for time-series optimization"
echo "  ✓ Continuous aggregates (hourly and daily)"
echo "  ✓ Data retention (30 days for raw data)"
echo "  ✓ Compression for data older than 7 days"
echo "  ✓ Indexes for fast queries"
echo ""
echo "Next steps:"
echo "  1. Configure MQTT broker (Mosquitto)"
echo "  2. Start Metrics-Collector service"
echo "  3. Configure Prometheus to scrape metrics"
echo "  4. Set up Grafana dashboards"