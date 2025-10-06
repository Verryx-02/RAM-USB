// Database-Vault module for RAM-USB distributed backup system
// Implements secure credential storage with mTLS authentication and AES-256-GCM encryption
module database-vault

go 1.24.1

// Cryptographic utilities for Argon2id password hashing and secure salt generation
require golang.org/x/crypto v0.39.0

// PostgreSQL driver with connection pooling and prepared statements
require github.com/jackc/pgx/v5 v5.5.1

// System-level dependencies and PostgreSQL driver dependencies
require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
)
