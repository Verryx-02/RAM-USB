// Package server holds Storage-Service's connection-acceptance identity for
// ST-F-01: the organization every mTLS client connecting to it must carry.
// cmd/storage-service/main.go reads AllowedClientOrganization to build its
// production HTTP handler chain via mtls.RequireOrganization, layered on top
// of the *tls.Config pki.NewServer's bootstrap certificate already produces
// (see that file's own package doc comment for why the check happens at the
// HTTP-request level here rather than via mtls.ServerConfig's
// handshake-level VerifyConnection).
package server

// AllowedClientOrganization is the organization ST-F-01 requires of every
// mTLS client connecting to Storage-Service. Database-Vault is the only
// component authorized to call Storage-Service's internal mTLS endpoints
// directly (SFTP access, ST-F-03, is a separate, non-mTLS access path with
// its own authentication and is not affected by this configuration).
//
// The SRS's ST-F-01 row previously quoted organization="Database-Vault"
// (hyphenated), inconsistent with every other component's own
// organization-check requirement (DV-F-01: "SecuritySwitch", SS-F-01:
// "EntryHub") and Database-Vault's own outbound call to Storage-Service
// (DV-F-09, see services/database-vault/internal/posix/client.go), which
// already used the hyphen-free PascalCase form for every organization
// literal. The SRS has since been corrected to organization="DatabaseVault"
// (no hyphen), matching this constant and the codebase's established
// convention — this is no longer an open discrepancy.
const AllowedClientOrganization = "DatabaseVault"
