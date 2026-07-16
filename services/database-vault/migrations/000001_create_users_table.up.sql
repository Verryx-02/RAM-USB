-- DV-F-08: schema for the user record Database-Vault persists atomically.
-- Column shapes match docs/design/diagrams/06-data-er-database-vault.puml
-- exactly; do not add, remove, or resize a column here without updating
-- that diagram first.
CREATE TABLE users (
    email_hash      CHAR(64) PRIMARY KEY,
    email_encrypted BYTEA NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    ssh_public_key  TEXT NOT NULL UNIQUE,
    posix_username  CHAR(10) NOT NULL,
    registered_at   TIMESTAMP NOT NULL
);
