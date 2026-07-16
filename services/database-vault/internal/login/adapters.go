package login

import (
	"context"

	"github.com/Verryx-02/RAM-USB/services/database-vault/internal/storage"
)

// StorageAdapter adapts storage.GetPasswordHash — a free function taking a
// storage.Querier — to the Storage interface, binding a single
// storage.Querier so a production caller can pass one value satisfying
// Storage. Same "narrow interface + adapter over a free function" pattern
// as the registration package's StorageAdapter/POSIXAdapter over
// storage.SaveUser/storage.DeleteUser/posix.CreatePOSIXUser.
type StorageAdapter struct {
	DB storage.Querier
}

// GetPasswordHash implements Storage.
func (a StorageAdapter) GetPasswordHash(ctx context.Context, emailHash string) (string, error) {
	return storage.GetPasswordHash(ctx, a.DB, emailHash)
}
