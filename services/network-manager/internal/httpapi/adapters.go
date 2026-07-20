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
// CreateMeshUser returns both the pre-auth key string (relayed to the
// client, UC-01 step 7-8) and the key's numeric Headscale ID
// (preAuthKeyID) - Handler.CreateMeshUser persists the latter via
// MeshUserStore.RecordPreAuthKeyID, since GrantStorageAccess needs it at
// every future login (see internal/headscale/client.go's package doc
// comment, "Bug fix" section, for the full root cause this replaced).
//
// GrantStorageAccess takes the pre-auth-key ID (looked up by
// Handler.Grant via MeshUserStore.PreAuthKeyIDForEmail, not the raw
// email) and returns the granted node's Headscale node ID (NM-F-11:
// Handler.Grant needs it to persist which node the grant belongs to, so
// NM-F-10's sweep can revoke the exact same node later without repeating
// this lookup).
type MeshProvisioner interface {
	CreateMeshUser(ctx context.Context, email string) (preAuthKey string, preAuthKeyID uint64, err error)
	GrantStorageAccess(ctx context.Context, preAuthKeyID uint64) (nodeID uint64, err error)
}

// HeadscaleAdapter adapts a headscale.Service (a real gRPC-backed client,
// or a test fake) into a MeshProvisioner.
type HeadscaleAdapter struct {
	Service headscale.Service
}

func (a HeadscaleAdapter) CreateMeshUser(ctx context.Context, email string) (string, uint64, error) {
	return headscale.CreateMeshUser(ctx, a.Service, email)
}

func (a HeadscaleAdapter) GrantStorageAccess(ctx context.Context, preAuthKeyID uint64) (uint64, error) {
	return headscale.GrantStorageAccess(ctx, a.Service, preAuthKeyID)
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

// MeshUserStore is the narrow interface Handler needs against
// internal/grants.Store's permanent mesh_users table (see that package's
// own doc comment): persist (NM-F-08, at registration) and look up
// (NM-F-09, at every login) the Headscale pre-auth-key ID recorded for an
// email. A real *grants.Store already satisfies this interface directly
// through Go's structural typing (its RecordPreAuthKeyID/
// PreAuthKeyIDForEmail methods have these exact signatures) - no adapter
// type is needed, same shape as GrantRecorder above.
//
// Unlike GrantRecorder (whose persistence failure is logged loudly but
// does not fail the request - NM-F-11's grant already succeeded at
// Headscale, and the sweep is a durability nicety), a MeshUserStore
// failure is treated as fatal by Handler.CreateMeshUser: without this row,
// GrantStorageAccess can never find this user's node again, at any future
// login, for the lifetime of the account - a silently "successful"
// registration response would be actively misleading.
type MeshUserStore interface {
	RecordPreAuthKeyID(ctx context.Context, email string, preAuthKeyID uint64) error
	PreAuthKeyIDForEmail(ctx context.Context, email string) (preAuthKeyID uint64, found bool, err error)
}
