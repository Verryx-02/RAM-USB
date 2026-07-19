package httpapi

import (
	"context"
	"time"

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
//
// GrantStorageAccess returns the granted node's Headscale node ID
// (NM-F-11: Handler.Grant needs it to persist which node the grant
// belongs to, so NM-F-10's sweep can revoke the exact same node later
// without repeating the email->user->node lookup).
type MeshProvisioner interface {
	CreateMeshUser(ctx context.Context, email string) (string, error)
	GrantStorageAccess(ctx context.Context, email string) (nodeID uint64, err error)
}

// HeadscaleAdapter adapts a headscale.Service (a real gRPC-backed client,
// or a test fake) into a MeshProvisioner.
type HeadscaleAdapter struct {
	Service headscale.Service
}

func (a HeadscaleAdapter) CreateMeshUser(ctx context.Context, email string) (string, error) {
	return headscale.CreateMeshUser(ctx, a.Service, email)
}

func (a HeadscaleAdapter) GrantStorageAccess(ctx context.Context, email string) (uint64, error) {
	return headscale.GrantStorageAccess(ctx, a.Service, email)
}

// GrantRecorder is the narrow interface Handler.Grant needs against
// internal/grants.Store to satisfy NM-F-11: persist a grant's node,
// tag, and expiry so NM-F-10's sweep survives a Network-Manager
// restart. A real *grants.Store already satisfies this interface
// directly through Go's structural typing (its RecordGrant method has
// this exact signature) - no adapter type is needed, same shape already
// used for paho's mqtt.Client (DV-F-16/17) and headscale.Service itself.
type GrantRecorder interface {
	RecordGrant(ctx context.Context, email string, nodeID uint64, tag string, expiresAt time.Time) error
}
