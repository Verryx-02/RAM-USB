#!/bin/bash

echo "============================================"
echo "Database-Vault PostgreSQL Schema Setup"
echo "============================================"

# Check if PostgreSQL is running
if ! pg_isready >/dev/null 2>&1; then
    echo "Error: PostgreSQL is not running"
    echo "Start with: brew services start postgresql"
    exit 1
fi

echo "PostgreSQL is running"
echo "PostgreSQL superuser: $(whoami)"

# Step 1: Create database and user
echo "1 Creating database and user..."

createdb ramusb_vault 2>/dev/null || echo "   Database may already exist"

psql postgres << 'EOF'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ramusb_user') THEN
        CREATE USER ramusb_user WITH ENCRYPTED PASSWORD 'ramusb_secure_2024';
        RAISE NOTICE 'User ramusb_user created';
    ELSE
        RAISE NOTICE 'User ramusb_user already exists';
    END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE ramusb_vault TO ramusb_user;
EOF

psql ramusb_vault << 'EOF'
GRANT ALL ON SCHEMA public TO ramusb_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO ramusb_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ramusb_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ramusb_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ramusb_user;
EOF

# Step 2-5: Run schema files
echo "2 Creating users table..."
psql ramusb_vault -f schema/001_create_tables.sql

echo "3 Creating indexes..."
psql ramusb_vault -f schema/002_create_indexes.sql

echo "4 Creating triggers..."
psql ramusb_vault -f schema/003_create_triggers.sql

echo "5 Creating constraints..."
psql ramusb_vault -f schema/004_create_constraints.sql

echo "Setup completed!"
echo ""
echo "Set environment variables:"
echo "export DATABASE_URL='postgres://ramusb_user:ramusb_secure_2024@localhost:5432/ramusb_vault?sslmode=disable'"
echo "export RAMUSB_ENCRYPTION_KEY=\$(openssl rand -hex 32)"