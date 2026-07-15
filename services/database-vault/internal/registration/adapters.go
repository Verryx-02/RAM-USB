package registration

import (
	"context"
	"net/http"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/posix"
	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// Storage is the subset of persistence operations Register needs: saving a
// new user record (DV-F-08) and deleting one as a compensating rollback
// (DV-F-10). Depending on this narrow interface, rather than on
// storage.Beginner directly, lets tests substitute a hand-written fake
// (CONTRIBUTING.md §7.5) without a real database — same pattern as
// storage.Beginner/storage.Tx being narrower than the full pgx interfaces
// they're built on.
type Storage interface {
	SaveUser(ctx context.Context, record storage.UserRecord) error
	DeleteUser(ctx context.Context, emailHash string) error
}

// POSIXProvisioner is the subset of Storage-Service interaction Register
// needs: requesting POSIX-user creation (DV-F-09) and waiting for the
// result.
type POSIXProvisioner interface {
	CreatePOSIXUser(ctx context.Context, username string) error
}

// StorageAdapter adapts storage.SaveUser/storage.DeleteUser — free functions
// each taking a storage.Beginner — to the Storage interface, binding a
// single storage.Beginner so a production caller can pass one value
// satisfying Storage.
type StorageAdapter struct {
	DB storage.Beginner
}

// SaveUser implements Storage.
func (a StorageAdapter) SaveUser(ctx context.Context, record storage.UserRecord) error {
	return storage.SaveUser(ctx, a.DB, record)
}

// DeleteUser implements Storage.
func (a StorageAdapter) DeleteUser(ctx context.Context, emailHash string) error {
	return storage.DeleteUser(ctx, a.DB, emailHash)
}

// POSIXAdapter adapts posix.CreatePOSIXUser — a free function taking an
// *http.Client and a base URL — to the POSIXProvisioner interface, binding
// both so a production caller can pass one value satisfying
// POSIXProvisioner.
type POSIXAdapter struct {
	Client  *http.Client
	BaseURL string
}

// CreatePOSIXUser implements POSIXProvisioner.
func (a POSIXAdapter) CreatePOSIXUser(ctx context.Context, username string) error {
	return posix.CreatePOSIXUser(ctx, a.Client, a.BaseURL, username)
}
