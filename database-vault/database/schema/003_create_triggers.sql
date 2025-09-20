-- Triggers creation for automatic timestamp management
-- Run on ramusb_vault database: psql -d ramusb_vault -f 004_create_triggers.sql


-- Function to automatically update updated_at timestamp on any UPDATE operation
-- Ensures audit trail accuracy without application-level intervention
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    -- Set updated_at to current timestamp for any UPDATE operation
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger that automatically calls update function before any UPDATE on users table
-- Guarantees updated_at is always current without manual intervention
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

\echo 'Triggers created successfully - updated_at will auto-update on modifications'