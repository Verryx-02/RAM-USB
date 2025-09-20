-- Data validation constraints for security and integrity
-- Run on ramusb_vault database: psql -d ramusb_vault -f 005_create_constraints.sql


-- Email hash validation: SHA-256 hex output (current implementation)
-- Flexible for future algorithm changes while maintaining security
ALTER TABLE users ADD CONSTRAINT chk_email_hash_format 
    CHECK (LENGTH(email_hash) = 64 AND email_hash ~ '^[a-f0-9]+$');

-- Email salt validation: cryptographic salt format (current: 16 bytes hex)
-- Allows flexibility for different salt sizes in future
ALTER TABLE users ADD CONSTRAINT chk_email_salt_format 
    CHECK (LENGTH(email_salt) >= 16 AND email_salt ~ '^[a-f0-9]+$');

-- Password hash validation: Argon2id output format (current: 32 bytes hex)  
-- Flexible for different Argon2id parameter changes
ALTER TABLE users ADD CONSTRAINT chk_password_hash_format 
    CHECK (LENGTH(password_hash) = 64 AND password_hash ~ '^[a-f0-9]+$');

-- Password salt validation: cryptographic salt format (current: 16 bytes hex)
-- Allows flexibility for different salt sizes in future
ALTER TABLE users ADD CONSTRAINT chk_password_salt_format 
    CHECK (LENGTH(password_salt) >= 16 AND password_salt ~ '^[a-f0-9]+$');

-- SSH public key validation: support for common algorithms with appropriate length ranges
-- Based on validation logic from utils/validation.go
ALTER TABLE users ADD CONSTRAINT chk_ssh_key_format 
    CHECK (
        (ssh_public_key LIKE 'ssh-rsa %' AND LENGTH(ssh_public_key) BETWEEN 300 AND 800) OR
        (ssh_public_key LIKE 'ssh-ed25519 %' AND LENGTH(ssh_public_key) BETWEEN 80 AND 120) OR
        (ssh_public_key LIKE 'ecdsa-sha2-nistp256 %' AND LENGTH(ssh_public_key) BETWEEN 150 AND 200) OR
        (ssh_public_key LIKE 'ecdsa-sha2-nistp384 %' AND LENGTH(ssh_public_key) BETWEEN 170 AND 220) OR
        (ssh_public_key LIKE 'ecdsa-sha2-nistp521 %' AND LENGTH(ssh_public_key) BETWEEN 190 AND 250) OR
        (ssh_public_key LIKE 'sk-ssh-ed25519@openssh.com %' AND LENGTH(ssh_public_key) BETWEEN 100 AND 140) OR
        (ssh_public_key LIKE 'sk-ecdsa-sha2-nistp256@openssh.com %' AND LENGTH(ssh_public_key) BETWEEN 180 AND 240)
    );

-- Encrypted email validation: must be valid base64 format (AES-256-GCM output)
-- Base64 pattern: letters, numbers, +, /, with optional padding (=)
ALTER TABLE users ADD CONSTRAINT chk_encrypted_email_format 
    CHECK (
        encrypted_email ~ '^[A-Za-z0-9+/]+={0,2}$' 
        AND LENGTH(encrypted_email) >= 16  -- Minimum encrypted content
        AND LENGTH(encrypted_email) <= 8192 -- Reasonable maximum
    );

\echo 'All data validation constraints created successfully'
\echo 'Database schema setup complete - ready for Database-Vault operations'