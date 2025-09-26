#!/bin/bash

echo "============================================"
echo "Database-Vault PostgreSQL Schema Setup"
echo "============================================"

# Check if PostgreSQL is running
if ! pg_isready >/dev/null 2>&1; then
    echo "Error: PostgreSQL is not running"
    echo "Start with: brew services start postgresql@17"
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

# Step 6: Configure PostgreSQL SSL (optional but recommended)
echo "6 Configuring PostgreSQL SSL..."

# Detect PostgreSQL data directory based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS with Homebrew
    PGDATA=$(brew --prefix)/var/postgresql@17
    PG_CTL="brew services restart postgresql@17"
elif [[ -d "/var/lib/postgresql" ]]; then
    # Linux typical location
    PGDATA="/var/lib/postgresql/17/main"
    PG_CTL="sudo systemctl restart postgresql"
else
    echo "   Warning: Could not detect PostgreSQL data directory"
    echo "   Skipping SSL configuration"
    PGDATA=""
fi

if [ ! -z "$PGDATA" ] && [ -d "$PGDATA" ]; then
    echo "   PostgreSQL data directory: $PGDATA"
    
    # Check if certificates exist
    CERT_DIR="../../certificates/postgresql"
    if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
        echo "   Found SSL certificates, configuring PostgreSQL..."
        
        # Copy certificates to PostgreSQL data directory
        cp "$CERT_DIR/server.crt" "$PGDATA/server.crt" 2>/dev/null || sudo cp "$CERT_DIR/server.crt" "$PGDATA/server.crt"
        cp "$CERT_DIR/server.key" "$PGDATA/server.key" 2>/dev/null || sudo cp "$CERT_DIR/server.key" "$PGDATA/server.key"
        
        # Set correct permissions
        chmod 600 "$PGDATA/server.key" 2>/dev/null || sudo chmod 600 "$PGDATA/server.key"
        chmod 644 "$PGDATA/server.crt" 2>/dev/null || sudo chmod 644 "$PGDATA/server.crt"
        
        # Enable SSL in postgresql.conf
        if [ -f "$PGDATA/postgresql.conf" ]; then
            # Check if SSL is already configured
            if grep -q "^ssl = " "$PGDATA/postgresql.conf"; then
                # Update existing SSL configuration
                sed -i.bak 's/^ssl = .*/ssl = on/' "$PGDATA/postgresql.conf" 2>/dev/null || \
                sudo sed -i.bak 's/^ssl = .*/ssl = on/' "$PGDATA/postgresql.conf"
            else
                # Add SSL configuration
                echo "ssl = on" >> "$PGDATA/postgresql.conf" 2>/dev/null || \
                echo "ssl = on" | sudo tee -a "$PGDATA/postgresql.conf" > /dev/null
            fi
            echo "   SSL enabled in postgresql.conf"
        fi
        
        # Restart PostgreSQL to apply changes
        echo "   Restarting PostgreSQL to apply SSL configuration..."
        eval $PG_CTL
        sleep 2
        
        echo "   SSL configuration completed successfully"
    else
        echo "   SSL certificates not found in $CERT_DIR"
        echo "   Run 'cd ../../scripts && ./generate_key.sh' to generate certificates"
        echo "   Continuing without SSL..."
    fi
else
    echo "   PostgreSQL data directory not found, skipping SSL setup"
fi

echo "Setup completed!"
echo ""
echo "Set environment variables:"
echo "# For SSL connection (default):"
echo "export DATABASE_URL='postgres://ramusb_user:ramusb_secure_2024@localhost:5432/ramusb_vault?sslmode=require'"
echo ""
echo "# For non-SSL connection (development without certificates):"
echo "export DATABASE_URL='postgres://ramusb_user:ramusb_secure_2024@localhost:5432/ramusb_vault?sslmode=disable'"
echo ""
echo "export RAMUSB_ENCRYPTION_KEY=\$(openssl rand -hex 32)"