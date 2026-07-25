// Package mesh embeds a Headscale/Tailscale mesh node directly into a
// backend service process, via tailscale.com/tsnet (an in-process,
// userspace WireGuard client - no root, no system daemon, no
// system-level "tailscale up"). This completes SS-F-01/DV-F-01's "access
// to the private mesh network" acceptance clause for the services that
// use it: until this package existed, Security-Switch and Database-Vault
// only ever communicated over ramusb-net, a single-host Docker bridge -
// Network-Manager's Headscale ACL rules (NM-F-02,
// services/network-manager/internal/headscale/policy.go) had no real mesh
// node to apply to.
//
// This is a different integration shape from user-client's own
// internal/mesh package (CL-F-04): that package shells out to the user's
// already-installed system "tailscale" binary, because SRS §2.6 assumes
// the *user* has Tailscale installed separately. A backend service has no
// such assumption to rely on and no interactive user to run "tailscale
// up" - so it embeds tsnet directly instead.
//
// # Reachability guarantee
//
// tsnet's own package doc states the property this package exists to
// provide: "Calling Server.Listen or Server.Dial routes traffic
// exclusively over the tailnet." A Server.Listen listener is never bound
// on the container's real network interface at all (tsnet runs a
// userspace gVisor netstack, entirely separate from the host/container
// TCP/IP stack) - so a connection attempt from outside the mesh (e.g.
// plain ramusb-net or localhost) to that same logical address has no real
// socket to reach and fails outright, not merely by policy. See
// mesh_integration_test.go for the empirical demonstration of this
// property against a real Headscale server.
//
// # Key distribution
//
// Every node's pre-auth key (Config.AuthKey) is minted manually by the
// operator via the Headscale CLI (docker exec into the Headscale
// container), exactly the same operator-driven pattern CA-F-04 already
// established for Certificate-Authority bootstrap tokens - no
// Network-Manager code change is required to support this. See each
// service's deployments/compose/*.yml for the exact minting command.
//
// # Mesh hostname resolution
//
// Confirmed live against a real Headscale server: a bare MagicDNS short
// hostname passed to Dial does NOT reliably resolve through tsnet's
// in-process netstack. tsnet.Server.Dial ultimately calls
// tsdial.Dialer.UserDial, which does try an in-memory MagicDNS map first
// (populated from the last NetworkMap the control server pushed to this
// node) before ever falling back to the host's own net.Resolver -
// but immediately after Up returns (Up only waits for backend state
// Running, not for a full NetworkMap that already includes a peer
// created moments earlier), that in-memory map can still be empty or
// stale for a peer this same run just joined. When it misses, UserDial
// falls through to a real net.Resolver.LookupIP call, which in a Docker
// container hits the container's embedded DNS (127.0.0.11:53) - a
// server that has never heard of Headscale's tailnet names, producing
// "no such host". This is not the system-tailscaled OS-resolver-
// integration gotcha tracked at tailscale/tailscale#15260 (tsnet never
// touches /etc/resolv.conf at all); it is a NetworkMap propagation race
// specific to dialing a peer immediately after joining.
//
// Dial works around this deterministically: if addr's host is not
// already a literal IP, it polls this node's own LocalClient().Status
// (the same LocalAPI a real "tailscale status" would query) for a peer
// whose HostName or MagicDNS short name matches, until found or ctx is
// done, then dials that peer's resolved Tailscale IP directly -
// bypassing tsnet's passive, timing-sensitive in-memory DNS map
// entirely. TailscaleIPs is kept as a lower-level building block for a
// caller that already knows its peer's IP and wants to skip resolution.
//
// # Data-plane readiness is NOT a resolution gate
//
// Confirmed live against a real Headscale server: even once a peer's
// hostname/IP is visible in Status (proving only that the control-plane
// join/NetworkMap propagation completed), the WireGuard data plane
// between two nodes that joined moments apart can still be mid-
// handshake. An earlier version of this package tried to have
// resolveAddr wait for genuine data-plane readiness before returning a
// peer's IP - specifically, ipnstate.PeerStatus's LastHandshake field
// ("with local wireguard" per its own doc comment, i.e. the last time
// this node's own WireGuard completed a cryptographic handshake with
// that peer) or, as a fallback, CurAddr ("one of Addrs, or unique if
// roaming") / Relay ("DERP region") being non-empty.
//
// That approach deadlocked in practice: confirmed live, two nodes that
// complete their control-plane join within seconds of each other can sit
// indefinitely with LastHandshake still zero and CurAddr/Relay both
// empty, because a WireGuard/tsnet data-plane handshake is lazy - it is
// only triggered by a real attempt to send traffic to that peer (a real
// Dial), not established proactively just because both nodes are online
// and mutually visible in each other's NetworkMap. A resolveAddr that
// blocks on that same signal before ever handing back an IP for Dial to
// use creates a circular stall: the signal this code waits for only
// becomes true as a side effect of the very Dial this code is blocking.
//
// resolveAddr therefore only waits for a peer's hostname to become
// visible in this node's mesh status (control-plane join/NetworkMap
// propagation, see "Mesh hostname resolution" above) - not for any
// data-plane signal. Dial's own retry-with-backoff loop around the whole
// resolve-then-dial cycle (bounded only by the caller's ctx, no extra
// timeout invented) is what makes real, repeated Dial attempts against
// that resolved IP - each attempt is itself the trigger that eventually
// establishes the lazy WireGuard handshake, and the loop keeps retrying
// until one such attempt lands after that handshake completes. This
// benefits every real caller through this same code path (e.g.
// Security-Switch's SS-F-04 call to Database-Vault via
// buildDatabaseVaultClient), not just this package's own tests.
//
// # Control-plane certificate trust in a distroless container
//
// tsnet's own control-plane dial (its HTTPS connection to ControlURL,
// carrying the join handshake Up performs) never sets tls.Config.RootCAs
// itself, so that one handshake falls back to Go's own
// crypto/x509.SystemCertPool - the ONLY place in this package, or in
// pkg/pki/pkg/mtls (every other TLS config in this codebase always sets
// an explicit RootCAs pool built from the RAM-USB CA), that depends on
// the host's OS-level trust store at all. On this project's default
// container base image (gcr.io/distroless/static-debian12:nonroot per
// the SRS's container base image policy, no shell/package manager, an
// immutable read-only trust store even if one existed) there is no way
// to run update-ca-certificates at runtime, so a self-signed dev-only
// Headscale certificate (third-party/headscale/dev-tls)
// can never be trusted through the OS trust store inside that image.
//
// Confirmed by reading the Go standard library's own source
// (crypto/x509/root_unix.go, loadSystemRoots): on Linux (and every other
// non-macOS Unix crypto/x509 builds for), SystemCertPool honors the
// SSL_CERT_FILE environment variable - if set to a non-empty value, it
// is the ONLY file read to build the process's root pool (replacing, not
// extending, the built-in default cert file search list), entirely
// independent of any real OS-level CA directory or package manager.
// crypto/x509.SystemCertPool's own doc comment documents this env var
// explicitly. crypto/tls caches the loaded pool the first time any
// nil-RootCAs handshake occurs in the process (a sync.Once
// internally) - since this package is confirmed the only in-process
// consumer of the system pool, and Config.ControlCAFile is applied
// before ts.Up's first control-plane dial (the first TLS handshake this
// process ever performs), there is no ordering race to worry about.
//
// Config.ControlCAFile (optional, empty by default) supplies this
// mechanism: Up reads and validates that file's PEM content, then sets
// SSL_CERT_FILE to its path so the next SystemCertPool() call (inside
// tsnet's control-plane dial) trusts exactly that certificate. This is a
// process-wide environment mutation, acceptable here specifically
// because nothing else in this process's dependency graph relies on the
// system pool (see above) - it must not be copied into a context where
// that assumption no longer holds. Per this project's convention for
// every other dev-only secret/certificate (see
// third-party/mosquitto/generate-dev-certs.sh and CONTRIBUTING.md), the
// certificate itself is generated/rotated at runtime and mounted as a
// volume, never baked into a Docker image at build time - see each
// service's deployments/compose/*.yml for the exact mount. Confirmed
// live: a statically built distroless test binary with no OS trust
// store at all still completes a real Headscale join once
// Config.ControlCAFile names that mounted dev certificate.
//
// # ACL policy: a denied path hangs until ctx expiry, it never errors
//
// Confirmed live against a real Headscale server carrying
// Network-Manager's database-mode ACL policy (NM-F-02,
// services/network-manager/internal/headscale/policy.go): every accept
// rule in that policy is tag-based, and Tailscale's packet filter is
// enforced at the RECEIVING node - so a node that joined from a pre-auth
// key minted without --tags matches no rule, and its inbound TCP SYNs are
// silently dropped. The failure shape at this layer is indistinguishable
// from a slow WireGuard handshake: the join succeeds, the peer stays
// visible in mesh status (NetworkMap visibility is NOT proof the filter
// allows traffic), resolution succeeds, and Dial then blocks for the
// caller's entire ctx without ever returning an error. There is no
// signal available here to fail faster on ("filtered" and "not yet
// handshaken" look identical from the dialing side), so Dial does not
// try to guess. Operationally: a Dial that hangs until ctx expiry
// despite successful resolution almost always means the two nodes' tags
// (or lack of them) match no ACL accept rule - mint every node's
// pre-auth key with the --tags the policy expects, as each service's
// deployments/compose/*.yml documents.
package mesh

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// peerResolvePollInterval is how often Dial re-polls this node's local
// mesh status while waiting for a not-yet-visible peer hostname to
// appear (see the package doc comment, "Mesh hostname resolution") -
// bounded solely by the caller's own ctx, no extra timeout layered on
// top.
const peerResolvePollInterval = 200 * time.Millisecond

// Config is this process's own mesh node identity and join parameters.
type Config struct {
	// Dir is a persistent directory tsnet uses to store this node's mesh
	// identity/state across restarts (its own Tailscale machine key,
	// etc.) - it must survive container restarts (backed by a dedicated
	// Docker volume in deployments/compose/*.yml), or this node re-joins
	// as a brand new machine every restart. Up creates Dir with 0700
	// permissions if it does not already exist.
	Dir string

	// Hostname is this node's name within the tailnet, and therefore its
	// MagicDNS short name (Headscale's dns.magic_dns=true, see
	// third-party/headscale/config/config.yaml) - how
	// this node's mesh peers address it.
	Hostname string

	// ControlURL is the self-hosted Headscale server's coordination URL
	// (RAM_USB_TAILSCALE_CONTROL_URL in every compose file that joins the
	// mesh) - deliberately never left empty, which would default to the
	// tailscale.com SaaS control plane instead of RAM-USB's own Headscale
	// instance.
	ControlURL string

	// AuthKey is a single-use Headscale pre-auth key, minted manually by
	// the operator (see this package's doc comment, "Key distribution").
	// Only consumed on this node's first join, per tsnet's own documented
	// precedence rules - ignored on any later restart once Dir already
	// holds this node's persisted state.
	AuthKey string

	// ControlCAFile optionally names a PEM file whose certificate this
	// process should trust when validating ControlURL's TLS certificate
	// (see this package's doc comment, "Control-plane certificate trust
	// in a distroless container"). Leave empty whenever ControlURL's
	// certificate already chains to a real, publicly trusted root - only
	// a dev-only self-signed Headscale certificate needs this set.
	ControlCAFile string
}

// Server wraps one embedded tsnet mesh node.
type Server struct {
	ts *tsnet.Server

	// closeOnce/closeErr make Close genuinely idempotent (see Close's doc
	// comment) - tsnet.Server.Close itself is documented as idempotent
	// but, confirmed live, a second real call returns "use of closed
	// network connection" instead of nil.
	closeOnce sync.Once
	closeErr  error
}

// Up validates cfg, ensures cfg.Dir exists, and joins the mesh - blocking
// until this node is authenticated and running. tsnet.Server.Up, not
// Listen/Start, is what actually waits for a completed join (verified via
// this package's own reading of tailscale.com/tsnet's godoc: Listen/Dial
// only call Start if not already started, and Start "connects the server
// to the tailnet" without necessarily waiting for the handshake Up's own
// doc comment guarantees - "Up connects the server to the tailnet and
// waits until it is running").
func Up(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("mesh: Dir must not be empty")
	}
	if cfg.Hostname == "" {
		return nil, fmt.Errorf("mesh: Hostname must not be empty")
	}
	if cfg.ControlURL == "" {
		return nil, fmt.Errorf("mesh: ControlURL must not be empty")
	}
	if cfg.AuthKey == "" {
		return nil, fmt.Errorf("mesh: AuthKey must not be empty")
	}

	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("mesh: create state directory %s: %w", cfg.Dir, err)
	}

	if cfg.ControlCAFile != "" {
		if err := trustControlCA(cfg.ControlCAFile); err != nil {
			return nil, err
		}
	}

	ts := &tsnet.Server{
		Dir:        cfg.Dir,
		Hostname:   cfg.Hostname,
		ControlURL: cfg.ControlURL,
		AuthKey:    cfg.AuthKey,
		// Logf left nil: tsnet's own doc comment says "if unset, logs are
		// discarded" - the correct default here, not a gap to fill with a
		// no-op, since this project's own logging goes through log/slog
		// (CONTRIBUTING.md §7.4), not tsnet's internal logger.
	}

	if _, err := ts.Up(ctx); err != nil {
		return nil, fmt.Errorf("mesh: join tailnet as %q: %w", cfg.Hostname, err)
	}

	return &Server{ts: ts}, nil
}

// trustControlCA validates that path contains at least one well-formed PEM
// certificate (failing closed, RD-04, rather than silently letting an
// unreadable/malformed file surface only much later as a cryptic
// control-plane TLS error), then sets SSL_CERT_FILE to path - see this
// package's doc comment, "Control-plane certificate trust in a distroless
// container", for the full mechanism and why this process-wide env var
// mutation is safe here specifically.
func trustControlCA(path string) error {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // path is Config.ControlCAFile, an operator-supplied deployment setting, not attacker input
	if err != nil {
		return fmt.Errorf("mesh: read ControlCAFile %s: %w", path, err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("mesh: ControlCAFile %s contains no valid PEM certificate", path)
	}
	if err := os.Setenv("SSL_CERT_FILE", path); err != nil {
		return fmt.Errorf("mesh: set SSL_CERT_FILE for control-plane cert trust: %w", err)
	}
	return nil
}

// Listen announces a listener reachable only from inside the mesh - see
// this package's doc comment, "Reachability guarantee".
func (s *Server) Listen(network, addr string) (net.Listener, error) {
	return s.ts.Listen(network, addr)
}

// DialFunc dials a network connection to addr, exactly the shape
// (*Server).Dial and (*net.Dialer).DialContext both already implement.
// pkg/metrics.NewClient and pkg/pki.NewClientWithDialer/RouteThroughDialer
// each accept one, so a mesh-joined service's own meshNode.Dial can be
// passed directly to route that package's outbound traffic through this
// server's mesh identity instead of plain DNS/TCP (NET-F-01, NM-F-04).
// Defined here, this type's one real implementation, rather than
// independently in each consuming package.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Dial connects to addr over the mesh only, never falling back to a
// plain network dial - this is what makes a caller's outbound call
// (e.g. Security-Switch's SS-F-04 call to Database-Vault) pass
// exclusively through the private mesh network, completing SS-F-01/
// DV-F-01's "access to the private mesh network" acceptance clause on the
// calling side.
//
// If addr's host is a MagicDNS short hostname rather than a literal IP,
// Dial resolves it itself via this node's local mesh status before
// dialing - see the package doc comment, "Mesh hostname resolution". The
// resolve-then-dial cycle itself is retried with backoff, bounded only
// by ctx: resolution alone does not prove the WireGuard data plane to
// that peer is up yet (see "Data-plane readiness is NOT a resolution
// gate"), so a dial issued right after resolution can still fail or hang
// once or twice before the lazy handshake it itself triggers completes.
func (s *Server) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var lastErr error
	for {
		resolved, err := s.resolveAddr(ctx, addr)
		if err != nil {
			return nil, err
		}

		conn, err := s.ts.Dial(ctx, network, resolved)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("mesh: dial %q: %w (last dial attempt error: %w)", addr, ctx.Err(), lastErr)
		case <-time.After(peerResolvePollInterval):
		}
	}
}

// resolveAddr rewrites addr's host to a literal mesh IP if it names a
// peer by MagicDNS short hostname, leaving addr untouched if its host is
// already a literal IP or if addr isn't a well-formed host:port (in
// which case s.ts.Dial itself reports the malformed-address error). It
// waits only for the peer's hostname to appear in this node's mesh
// status (control-plane join/NetworkMap propagation) - deliberately not
// for any WireGuard data-plane signal, see the package doc comment,
// "Data-plane readiness is NOT a resolution gate": that signal only
// becomes true as a side effect of a real Dial attempt, so waiting for
// it here would block on a condition this code itself never triggers.
// Dial's own retry-with-backoff loop around the whole resolve-then-dial
// cycle is what drives the real attempts that data-plane readiness
// actually depends on.
func (s *Server) resolveAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}

	lc, err := s.ts.LocalClient()
	if err != nil {
		return "", fmt.Errorf("mesh: get local client to resolve peer %q: %w", host, err)
	}

	for {
		ip, found, err := lookupPeerIP(ctx, lc, host)
		if err != nil {
			return "", fmt.Errorf("mesh: query mesh status to resolve peer %q: %w", host, err)
		}
		if found {
			return net.JoinHostPort(ip.String(), port), nil
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("mesh: no mesh peer found with hostname %q before context deadline: %w", host, ctx.Err())
		case <-time.After(peerResolvePollInterval):
		}
	}
}

// lookupPeerIP searches this node's current mesh status for a peer whose
// HostName or MagicDNS short name (the label before the first dot of its
// DNSName) matches host, case-insensitively - a peer merely known to the
// control plane, not proof of an established WireGuard data plane to it
// (see the package doc comment, "Data-plane readiness is NOT a
// resolution gate") - and returns that peer's first Tailscale IP (IPv4
// preferred).
func lookupPeerIP(ctx context.Context, lc *local.Client, host string) (netip.Addr, bool, error) {
	st, err := lc.Status(ctx)
	if err != nil {
		return netip.Addr{}, false, err
	}

	for _, peer := range st.Peer {
		if peer == nil {
			continue
		}
		if !matchesHostname(peer.HostName, host) && !matchesHostname(peer.DNSName, host) {
			continue
		}
		for _, ip := range peer.TailscaleIPs {
			if ip.Is4() {
				return ip, true, nil
			}
		}
		if len(peer.TailscaleIPs) > 0 {
			return peer.TailscaleIPs[0], true, nil
		}
	}
	return netip.Addr{}, false, nil
}

// matchesHostname reports whether name (a peer's HostName, or its
// DNSName which is a trailing-dot FQDN like "host.<suffix>.") equals
// host once name is reduced to its first label and both are compared
// case-insensitively.
func matchesHostname(name, host string) bool {
	name = strings.TrimSuffix(name, ".")
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	return strings.EqualFold(name, host)
}

// TailscaleIPs returns this node's own IPv4/IPv6 mesh addresses. Dial
// resolves a peer's IP for its own caller internally (see the package
// doc comment, "Mesh hostname resolution") - this method is a
// lower-level building block for a caller of this node's own address
// specifically (e.g. the test proving the reachability guarantee), not
// something callers dialing a peer need to use themselves.
func (s *Server) TailscaleIPs() (ip4, ip6 netip.Addr) {
	return s.ts.TailscaleIPs()
}

// Close shuts down this node's mesh membership. Idempotent: calling Close
// more than once always returns the same result as the first real call,
// never a fresh error - guaranteed by this method itself (via sync.Once),
// not by tsnet.Server.Close alone, which is documented as idempotent but,
// confirmed live, actually returns "use of closed network connection" on
// a second real call. Has an internal 5s timeout (tsnet's own doc
// comment); must not be called before or concurrently with Up, per
// tsnet's own doc comment on Server.Close.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.ts.Close()
	})
	return s.closeErr
}
