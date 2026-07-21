package httpapi

import (
	"context"
	"net/http"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/dbvault"
	"github.com/Verryx-02/RAM-USB/services/security-switch/internal/networkmanager"
)

// DatabaseVaultClient is the narrow interface Handler needs to forward a
// request to Database-Vault (SS-F-04). DBVaultAdapter binds it to the real
// dbvault.Register/dbvault.Login free functions, same "narrow interface +
// adapter over a free function" shape as
// services/database-vault/internal/registration/adapters.go's
// StorageAdapter/POSIXAdapter.
type DatabaseVaultClient interface {
	Register(ctx context.Context, req validation.RegisterRequest) dbvault.Result
	Login(ctx context.Context, req validation.LoginRequest) dbvault.Result
}

// DBVaultAdapter adapts an mTLS-configured *http.Client (verifying
// dbvault.OrganizationDatabaseVault, per SS-F-04) plus Database-Vault's
// base URL into a DatabaseVaultClient.
type DBVaultAdapter struct {
	Client  *http.Client
	BaseURL string
}

// Register satisfies DatabaseVaultClient by forwarding to
// dbvault.Register.
func (a DBVaultAdapter) Register(ctx context.Context, req validation.RegisterRequest) dbvault.Result {
	return dbvault.Register(ctx, a.Client, a.BaseURL, req)
}

// Login satisfies DatabaseVaultClient by forwarding to dbvault.Login.
func (a DBVaultAdapter) Login(ctx context.Context, req validation.LoginRequest) dbvault.Result {
	return dbvault.Login(ctx, a.Client, a.BaseURL, req)
}

// NetworkManagerClient is the narrow interface Handler needs to request a
// Storage-Service access grant after a successful login (SS-F-05), and to
// request a dedicated mesh user + pre-auth key after a successful
// registration (SS-F-09). email is the login/registration request's own
// email (already in scope at the call site), identifying the user's
// mesh node - not a value sourced from Database-Vault's response.
type NetworkManagerClient interface {
	GrantAccess(ctx context.Context, email string) error
	CreateMeshUser(ctx context.Context, email string) (preAuthKey string, err error)
}

// NetworkManagerAdapter adapts an mTLS-configured *http.Client (verifying
// networkmanager.OrganizationNetworkManager) plus Network-Manager's base
// URL into a NetworkManagerClient.
type NetworkManagerAdapter struct {
	Client  *http.Client
	BaseURL string
}

// GrantAccess satisfies NetworkManagerClient by forwarding to
// networkmanager.GrantAccess.
func (a NetworkManagerAdapter) GrantAccess(ctx context.Context, email string) error {
	return networkmanager.GrantAccess(ctx, a.Client, a.BaseURL, email)
}

// CreateMeshUser satisfies NetworkManagerClient by forwarding to
// networkmanager.CreateMeshUser.
func (a NetworkManagerAdapter) CreateMeshUser(ctx context.Context, email string) (string, error) {
	return networkmanager.CreateMeshUser(ctx, a.Client, a.BaseURL, email)
}
