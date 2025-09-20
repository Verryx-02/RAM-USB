-- Users table creation for Database-Vault secure credential storage
-- Run on ramusb_vault database: psql -d ramusb_vault -f 002_create_tables.sql


-- Users table for secure credential storage with email encryption and password hashing
CREATE TABLE users (
    -- Primary key: SHA-256 hash of email for fast zero-knowledge indexing
    email_hash VARCHAR(64) PRIMARY KEY,
    
    -- AES-256-GCM encrypted email with random nonce (base64 encoded)
    encrypted_email TEXT NOT NULL,
    
    -- Cryptographic salt for email encryption key derivation (hex encoded)
    email_salt VARCHAR(32) NOT NULL,
    
    -- Argon2id password hash (hex encoded)
    password_hash VARCHAR(64) NOT NULL,
    
    -- Cryptographic salt for password hashing (hex encoded)
    password_salt VARCHAR(32) NOT NULL,
    
    -- SSH public key for Storage-Service authentication
    ssh_public_key TEXT NOT NULL,
    
    -- Account creation timestamp for audit trail
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Last modification timestamp for security monitoring
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Last access timestamp for inactive account detection (NULL for never logged in)
    last_access_at TIMESTAMP NULL
);

\echo 'Users table created successfully'