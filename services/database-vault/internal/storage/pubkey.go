// Package storage adds, in this file, a second read path alongside
// lookup.go's GetPasswordHash: retrieving a user's stored ssh_public_key by
// posix_username rather than by
// email_hash. It exists for ST-F-11 ("on every user SFTP connection attempt,
// [Storage-Service] must retrieve the user's current public key from
// Database-Vault via AuthorizedKeysCommand"): sshd invokes
// AuthorizedKeysCommand with the connecting POSIX username as its argument,
// not an email address, so this is the identifier Storage-Service actually
// has at connection time — never the email_hash GetPasswordHash uses.
//
// It reuses the existing Querier interface (a single QueryRow call needs no
// new abstraction) and reads no other column.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// selectSSHPublicKeyByPosixUsernameSQL matches the schema in
// docs/design/diagrams/06-data-er-database-vault.puml, same as
// insertUserSQL/selectPasswordHashSQL. posix_username currently has no
// dedicated index of its own beyond the table's physical storage — see
// migrations/000002_add_posix_username_unique_index.up.sql, added alongside
// this file, for why one was needed for this query to be efficient and safe.
const selectSSHPublicKeyByPosixUsernameSQL = `SELECT ssh_public_key FROM users WHERE posix_username = $1`

// ErrPosixUsernameNotFound means no row matches the given posix_username.
// Unlike ErrUserNotFound (DV-F-13/DV-F-15's login lookup, which must never
// be distinguished from a wrong-password failure to an external, potentially
// adversarial caller), this lookup is only ever reached by Storage-Service
// over its own dedicated mTLS listener (organization="StorageService"), an
// already-authenticated internal service, not an end-user-facing
// authentication attempt. There is no analogous "wrong credential" case to
// blend this with, and no email-enumeration-style risk from a distinct
// not-found signal here — so callers are free to map this to a distinct
// HTTP 404, unlike ErrUserNotFound's DV-F-15-driven uniform-401 treatment.
var ErrPosixUsernameNotFound = errors.New("storage: no user found for this posix username")

// GetSSHPublicKeyByPosixUsername retrieves the stored ssh_public_key
// (DV-F-12's uniqueness target, ST-F-11's return value) for the user
// identified by posixUsername (DV-F-09's "user<xxxxxx>" format). A returned
// error wrapping ErrPosixUsernameNotFound (checked via errors.Is) means no
// row matched; any other error means the query itself failed.
func GetSSHPublicKeyByPosixUsername(ctx context.Context, db Querier, posixUsername string) (string, error) {
	var sshPublicKey string

	if err := db.QueryRow(ctx, selectSSHPublicKeyByPosixUsernameSQL, posixUsername).Scan(&sshPublicKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w", ErrPosixUsernameNotFound)
		}
		return "", fmt.Errorf("storage: query ssh public key by posix username: %w", err)
	}

	return sshPublicKey, nil
}
