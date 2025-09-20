/*
SQL query constants for PostgreSQL storage operations.

Provides prepared statement queries for secure database operations with
parameterized queries to prevent SQL injection. All queries use indexed
columns for optimal performance and follow zero-knowledge principles
using email_hash as primary identifier.
*/
package postgresql

const (
	// USER CREATION QUERIES
	// Insert new user with all encrypted and hashed fields
	insertUserQuery = `
		INSERT INTO users (
			email_hash, encrypted_email, email_salt,
			password_hash, password_salt, ssh_public_key,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// USER RETRIEVAL QUERIES
	// Get complete user record by email hash for authentication
	getUserByEmailHashQuery = `
		SELECT 
			email_hash, encrypted_email, email_salt,
			password_hash, password_salt, ssh_public_key,
			created_at, updated_at, last_access_at
		FROM users 
		WHERE email_hash = $1`

	// EXISTENCE CHECK QUERIES
	// Fast existence check using indexed email_hash column
	emailHashExistsQuery = `
		SELECT EXISTS(
			SELECT 1 FROM users WHERE email_hash = $1
		)`

	// SSH key uniqueness check across entire user base
	sshKeyExistsQuery = `
		SELECT EXISTS(
			SELECT 1 FROM users WHERE ssh_public_key = $1
		)`

	// USER UPDATE QUERIES
	// Update password with new hash and salt
	updatePasswordQuery = `
		UPDATE users 
		SET password_hash = $2, password_salt = $3, updated_at = NOW()
		WHERE email_hash = $1`

	// Update SSH public key with uniqueness validation
	updateSSHKeyQuery = `
		UPDATE users 
		SET ssh_public_key = $2, updated_at = NOW()
		WHERE email_hash = $1`

	// Update encrypted email with new salt (for key rotation)
	updateEncryptedEmailQuery = `
		UPDATE users 
		SET encrypted_email = $2, email_salt = $3, updated_at = NOW()
		WHERE email_hash = $1`

	// Update last access timestamp for security monitoring
	updateLastAccessQuery = `
		UPDATE users 
		SET last_access_at = NOW()
		WHERE email_hash = $1`

	// USER DELETION QUERIES
	// Permanent user deletion for GDPR compliance
	deleteUserQuery = `
		DELETE FROM users 
		WHERE email_hash = $1`

	// STATISTICS QUERIES
	// Get total user count for monitoring
	getTotalUsersQuery = `
		SELECT COUNT(*) FROM users`

	// Get active users (accessed within last 30 days)
	getActiveUsersQuery = `
		SELECT COUNT(*) 
		FROM users 
		WHERE last_access_at > NOW() - INTERVAL '30 days'`

	// Get registrations in last 24 hours
	getRegistrationsTodayQuery = `
		SELECT COUNT(*) 
		FROM users 
		WHERE created_at > NOW() - INTERVAL '24 hours'`

	// Get most recent registration timestamp
	getLastRegistrationQuery = `
		SELECT MAX(created_at) 
		FROM users`

	// Get database size for capacity monitoring
	getDatabaseSizeQuery = `
		SELECT pg_database_size(current_database())`

	// HEALTH CHECK QUERIES
	// Simple connectivity check
	healthCheckQuery = `SELECT 1`

	// Get active connection count
	getConnectionCountQuery = `
		SELECT COUNT(*) 
		FROM pg_stat_activity 
		WHERE datname = current_database()`
)
