// Package mesh implements CL-F-04: joining the private Headscale mesh
// network by shelling out to the user's already-installed system
// "tailscale" binary (SRS §2.6's own assumption - "the user is assumed to
// have installed the Tailscale client on their system before completing
// registration" - so this package never embeds tailscale.com/tsnet or any
// other in-process client library).
//
// CL-F-05 (resolving Storage-Service via MagicDNS) needs no code of its
// own here: once "tailscale up" succeeds with the default --accept-dns=true
// behavior, the OS's own resolver transparently resolves mesh hostnames
// for any later net.Dial/net.LookupHost call this Client makes (e.g.
// restic's own SFTP connection in CL-F-06/CL-F-07) - Tailscale's client
// integrates with the OS DNS manager once joined, so there is nothing for
// this package to implement beyond confirming "tailscale up" itself
// succeeded.
package mesh

import (
	"context"
	"errors"
	"fmt"

	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
)

// ErrJoinFailed wraps the tailscale binary's own combined output when
// "tailscale up" exits non-zero, so a caller can surface that output to
// the user (CL-F-04 explicitly requires flagging this clearly, not
// swallowing it - whether "tailscale up" needs elevated host-OS privileges
// is genuinely platform-dependent and unverified, so any non-zero exit is
// treated as a real, actionable failure, never assumed to be success).
var ErrJoinFailed = errors.New("mesh: tailscale up failed")

// Join implements CL-F-04: runs "tailscale up --login-server=loginServer
// --authkey=preauthKey" via runner, pointing the user's already-installed
// Tailscale client at the self-hosted Headscale coordination server
// instead of the default tailscale.com SaaS one. --accept-dns is left at
// its Tailscale default (true), which is what makes CL-F-05's MagicDNS
// resolution transparent afterward.
func Join(ctx context.Context, runner execrunner.Runner, loginServer, preauthKey string) error {
	if loginServer == "" {
		return fmt.Errorf("mesh: loginServer must not be empty")
	}
	if preauthKey == "" {
		return fmt.Errorf("mesh: preauthKey must not be empty")
	}

	output, err := runner.Run(ctx, nil, "tailscale", "up",
		"--login-server="+loginServer,
		"--authkey="+preauthKey,
	)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrJoinFailed, output)
	}
	return nil
}
