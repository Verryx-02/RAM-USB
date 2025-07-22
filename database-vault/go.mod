// Database-Vault module for R.A.M.-U.S.B. distributed backup system
// Implements secure credential storage with mTLS authentication and AES-256-GCM encryption
module database-vault

go 1.24.1

// Cryptographic utilities for Argon2id password hashing and secure salt generation
require golang.org/x/crypto v0.39.0

// System-level dependencies (automatically managed)
require golang.org/x/sys v0.33.0 // indirect
