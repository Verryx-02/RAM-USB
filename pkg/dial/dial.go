// Package dial defines the shared DialFunc abstraction used by any
// outbound-call package (pkg/metrics, pkg/pki) that needs to accept a
// caller-supplied dialer instead of always dialing plain DNS/TCP - for
// example a mesh-joined service's own tailscaled-backed dial, so that
// package's traffic is routed through that service's mesh identity
// instead. Kept in its own minimal package, independent of pkg/metrics
// and pkg/pki, so neither of those packages has to depend on the other
// just to share this type.
package dial

import (
	"context"
	"net"
)

// DialFunc dials a network connection to addr, exactly the shape
// (*net.Dialer).DialContext already implements. pkg/metrics.NewClient and
// pkg/pki.NewClientWithDialer/RouteThroughDialer each accept one, so a
// mesh-joined service's own dialer can be passed directly to route that
// package's outbound traffic through the mesh instead of plain DNS/TCP
// (NET-F-01, NM-F-04).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error) //nolint:revive // name kept for parity with pre-relocation pkg/mesh.DialFunc (KI-31); callers already reference it as dial.DialFunc
