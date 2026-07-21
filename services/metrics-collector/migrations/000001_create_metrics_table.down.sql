-- Reverses 000001_create_metrics_table.up.sql. Test-cleanup-only (see
-- internal/schema's own doc comment: Down() never runs against a real
-- database in production) - if_exists => true on both policy-removal
-- calls means this is safe to run even if a specific test run never got
-- far enough to add one of them. Dropping the hypertable itself cascades
-- away its chunks and any remaining background jobs automatically.
CALL remove_columnstore_policy('metrics', if_exists => true);
SELECT remove_retention_policy('metrics', if_exists => true);
DROP TABLE IF EXISTS metrics;
