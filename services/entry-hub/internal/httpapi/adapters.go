package httpapi

import (
	"context"
	"net/http"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
)

// SecuritySwitchClient is the narrow interface Handler needs to forward a
// request to Security-Switch and receive its response unchanged
// (EH-F-07, EH-F-08). SecuritySwitchAdapter binds it to the real
// securityswitch.Register/securityswitch.Login free functions, same
// "narrow interface + adapter over a free function" shape as
// services/security-switch/internal/httpapi/adapters.go's
// DBVaultAdapter/NetworkManagerAdapter.
type SecuritySwitchClient interface {
	Register(ctx context.Context, req validation.RegisterRequest) securityswitch.Result
	Login(ctx context.Context, req validation.LoginRequest) securityswitch.Result
}

// SecuritySwitchAdapter adapts an mTLS-configured *http.Client (verifying
// securityswitch.OrganizationSecuritySwitch, per EH-F-07) plus
// Security-Switch's base URL into a SecuritySwitchClient.
type SecuritySwitchAdapter struct {
	Client  *http.Client
	BaseURL string
}

func (a SecuritySwitchAdapter) Register(ctx context.Context, req validation.RegisterRequest) securityswitch.Result {
	return securityswitch.Register(ctx, a.Client, a.BaseURL, req)
}

func (a SecuritySwitchAdapter) Login(ctx context.Context, req validation.LoginRequest) securityswitch.Result {
	return securityswitch.Login(ctx, a.Client, a.BaseURL, req)
}
