#!/bin/bash

echo "============================================"
echo "Database-Vault PostgreSQL Testing Script"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if PostgreSQL is running
echo -e "${YELLOW}Step 1: Checking PostgreSQL status...${NC}"
if pg_isready >/dev/null 2>&1; then
    echo -e "${GREEN}PostgreSQL is running${NC}"
else
    echo -e "${RED}PostgreSQL is not running${NC}"
    echo "Start with: brew services start postgresql (macOS)"
    exit 1
fi

# Check if database exists
echo -e "\n${YELLOW}Step 2: Checking database existence...${NC}"
if psql -lqt | cut -d \| -f 1 | grep -qw ramusb_vault; then
    echo -e "${GREEN}Database 'ramusb_vault' exists${NC}"
else
    echo -e "${RED}Database 'ramusb_vault' does not exist${NC}"
    echo "Run: cd database-vault/database && ./setup.sh"
    exit 1
fi

# Test database connectivity
echo -e "\n${YELLOW}Step 3: Testing database connectivity...${NC}"
export DATABASE_URL="postgres://ramusb_user:ramusb_secure_2024@localhost:5432/ramusb_vault?sslmode=disable"

if psql "$DATABASE_URL" -c "SELECT 1" >/dev/null 2>&1; then
    echo -e "${GREEN}Database connection successful${NC}"
else
    echo -e "${RED}Database connection failed${NC}"
    echo "Check database credentials and permissions"
    exit 1
fi

# Check tables existence
echo -e "\n${YELLOW}Step 4: Checking table structure...${NC}"
TABLE_EXISTS=$(psql "$DATABASE_URL" -t -c "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')")
if [ "$TABLE_EXISTS" = " t" ]; then
    echo -e "${GREEN}Users table exists${NC}"
    
    # Show table structure
    echo -e "\nTable structure:"
    psql "$DATABASE_URL" -c "\d users" | head -20
else
    echo -e "${RED}Users table does not exist${NC}"
    echo "Run database setup script first"
    exit 1
fi

# Check indexes
echo -e "\n${YELLOW}Step 5: Checking indexes...${NC}"
INDEX_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'users'")
if [ $INDEX_COUNT -gt 0 ]; then
    echo -e "${GREEN}Indexes configured (found $INDEX_COUNT)${NC}"
else
    echo -e "${RED}No indexes found${NC}"
fi

# Show current user count
echo -e "\n${YELLOW}Step 6: Current database status...${NC}"
USER_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM users" 2>/dev/null || echo "0")
echo "Current user count: $USER_COUNT"

# Test query performance
echo -e "\n${YELLOW}Step 7: Testing query performance...${NC}"
echo "Testing email hash lookup..."
QUERY_TIME=$(psql "$DATABASE_URL" -t -c "EXPLAIN ANALYZE SELECT 1 FROM users WHERE email_hash = 'test_hash_that_does_not_exist'" 2>/dev/null | grep "Execution Time" | cut -d: -f2)
if [ ! -z "$QUERY_TIME" ]; then
    echo -e "${GREEN}Query execution successful${NC}"
    echo "Query execution time: $QUERY_TIME"
else
    echo -e "${YELLOW}Could not measure query performance${NC}"
fi

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}Database testing completed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Environment variables for Database-Vault:"
echo "export DATABASE_URL='$DATABASE_URL'"
echo "export RAMUSB_ENCRYPTION_KEY=$(openssl rand -hex 32)"
echo ""
echo "Ready to start Database-Vault server!"