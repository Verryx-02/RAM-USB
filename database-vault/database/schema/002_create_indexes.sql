-- Indexes creation for performance and security
-- Run on ramusb_vault database: psql -d ramusb_vault -f 003_create_indexes.sql


-- Unique constraint on SSH public key (prevents key reuse across users)
-- Critical for Storage-Service access control security
CREATE UNIQUE INDEX idx_users_ssh_key ON users(ssh_public_key);

-- Index for inactive user cleanup queries
-- Optimizes queries like: SELECT * FROM users WHERE last_access_at < NOW() - INTERVAL '90 days'
CREATE INDEX idx_users_last_access ON users(last_access_at);

-- Index for temporal audit queries and user registration analytics
-- Optimizes queries by creation date for reporting and monitoring
CREATE INDEX idx_users_created_at ON users(created_at);

-- Index for updated_at field for audit queries
-- Useful for tracking recent modifications and sync operations
CREATE INDEX idx_users_updated_at ON users(updated_at);

\echo 'All indexes created successfully'