package httpapi

import (
	"context"

	"github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// MeshProvisioner is the narrow interface Handler needs against
// internal/headscale: create a mesh user + pre-auth key (NM-F-08) and
// grant an existing node reachability toward Storage-Service (NM-F-09).
// HeadscaleAdapter binds it to the real headscale.CreateMeshUser/
// GrantStorageAccess free functions - same "narrow interface + adapter
// over a free function" shape as every other orchestration layer in this
// codebase (e.g. services/database-vault/internal/registration/
// adapters.go's StorageAdapter/POSIXAdapter).
type MeshProvisioner interface {
	CreateMeshUser(ctx context.Context, email string) (string, error)
	GrantStorageAccess(ctx context.Context, email string) error
}

// HeadscaleAdapter adapts a headscale.Service (a real gRPC-backed client,
// or a test fake) into a MeshProvisioner.
type HeadscaleAdapter struct {
	Service headscale.Service
}

func (a HeadscaleAdapter) CreateMeshUser(ctx context.Context, email string) (string, error) {
	return headscale.CreateMeshUser(ctx, a.Service, email)
}

func (a HeadscaleAdapter) GrantStorageAccess(ctx context.Context, email string) error {
	return headscale.GrantStorageAccess(ctx, a.Service, email)
}
