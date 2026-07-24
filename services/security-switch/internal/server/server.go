// Package server holds Security-Switch's connection-acceptance identity for
// SS-F-01: the organization every mTLS client connecting to it must carry.
// cmd/security-switch/main.go reads AllowedClientOrganization to build its
// production HTTP handler chain via mtls.RequireOrganization, layered on top
// of the *tls.Config pki.NewServer's bootstrap certificate already produces
// (see that file's own package doc comment for why the check happens at the
// HTTP-request level here rather than via mtls.ServerConfig's
// handshake-level VerifyConnection).
package server

// AllowedClientOrganization is the organization SS-F-01 requires of every
// mTLS client connecting to Security-Switch. Entry-Hub is the only
// component authorized to call Security-Switch directly.
const AllowedClientOrganization = "EntryHub"
