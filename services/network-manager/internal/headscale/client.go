// Package headscale is Network-Manager's client for Headscale's own REST
// API (github.com/juanfont/headscale v0.29.2), implementing NM-F-08
// (mesh-user + pre-auth-key creation), NM-F-09 (ACL-tag grant for
// reachability toward Storage-Service), and NM-F-10's revoke half.
//
// # Why REST, not gRPC (this session's architectural change)
//
// An earlier version of this package dialed Headscale's gRPC coordination
// API directly, with Headscale co-located inside this same
// network-manager container so that dial could stay loopback-only
// (NM-F-12's old wording: "restricted... by network placement"). That
// co-location was withdrawn this session after finding Headscale's own
// documented limitation (headscale.net's FAQ): "running headscale on a
// machine that is also in the tailnet it coordinates... is not
// supported" - Headscale's own coordination server can never safely join
// the private mesh it coordinates, so no network-placement-based
// restriction (mesh-only reachability, loopback binding) can apply to
// admin traffic reaching it at all; it must be reachable over the same
// public network as NM-F-14's coordination endpoint. NM-F-12 was reworded
// accordingly: admin traffic (pre-auth-key/ACL-tag operations) is now
// restricted by mutual TLS alone (RNF-SEC-04), not network placement.
//
// Headscale is now a fully separate deployment (deployments/compose/
// headscale.yml, deployments/docker/headscale/), fronted by a reverse
// proxy that terminates public TLS and enforces PKI-F-02's mTLS
// organization check (organization=NetworkManager) ONLY on the `/api/v1/*`
// path this package calls - see that Dockerfile's own doc comment for the
// full reverse-proxy design and why per-path (not per-listener) mTLS
// enforcement was necessary. Reaching Headscale's ADMIN API therefore
// means an ordinary HTTPS call through that proxy, exactly the same shape
// as any other outbound mTLS call this codebase already makes (pkg/pki),
// EXCEPT for one deliberate difference flagged clearly here: this is the
// ONE call in the entire system that crosses the PUBLIC network instead
// of the private mesh - Headscale's own "do not join your own tailnet"
// limitation leaves no mesh-based alternative. See cmd/network-manager/
// main.go's own package doc comment for the full outbound-client wiring.
// The REST API itself (not gRPC) is what that reverse proxy can path-match
// on at all: confirmed by reading github.com/juanfont/headscale@v0.29.2's
// hscontrol/app.go (createRouter/Serve) this session - `/api/v1/*` (the
// grpc-gateway-generated REST/JSON surface) is registered on the SAME
// chi.Router, and served on the SAME net.Listener (h.cfg.Addr, i.e.
// listen_addr), as every coordination-protocol route (/key, /ts2021,
// /register/{id}, ...); Headscale's separate gRPC listener
// (h.cfg.GRPCAddr) has no path structure a reverse proxy could distinguish
// requests by at all - a raw gRPC/HTTP2 frame carries no HTTP path a
// classic reverse proxy's location/route matching can inspect the way an
// ordinary REST request's path can. Switching from gRPC to REST is what
// makes path-based reverse-proxy dispatch (and therefore this whole
// mTLS-gated design) possible in the first place.
//
// # Wire shapes
//
// Confirmed directly against github.com/juanfont/headscale@v0.29.2's own
// generated OpenAPI/swagger definitions this session (gen/openapiv2/
// headscale/v1/headscale.swagger.json - the exact JSON request/response
// shapes grpc-gateway produces from the same .proto Headscale's gRPC API
// uses), not merely inferred from the gRPC message types the previous
// version of this file used:
//   - Every numeric ID (user/pre-auth-key/node) is a JSON STRING carrying a
//     uint64, not a JSON number - protobuf JSON's own well-known mapping
//     for a uint64 field (JSON numbers cannot safely represent the full
//     uint64 range). rest.go's parseID/formatID convert at this package's
//     one boundary; every exported function in this file still takes/
//     returns a real Go uint64, unchanged from the gRPC-based version.
//   - CreatePreAuthKeyRequest's Expiration is a JSON date-time string
//     (RFC 3339, encoding/json's own time.Time marshaling) - still always
//     set explicitly (see preAuthKeyExpiration's own doc comment): an
//     omitted Expiration is very likely treated as "never expires"
//     downstream, per the previous version's own investigation, and
//     nothing in the REST API's schema changes that risk.
//   - Headscale usernames (CreateUserRequest.Name) are still validated by
//     util.ValidateUsername (unchanged from the gRPC handler this session
//     confirmed calls the exact same internal validation regardless of
//     transport) - meshUsername's own reasoning is unchanged.
//   - SetTags is still a full-replace operation (POST /api/v1/node/{id}/
//     tags with a complete desired tag list, never a patch) - Headscale's
//     handler is the same Go function regardless of which transport
//     (gRPC or REST/grpc-gateway) invoked it, so this file's own
//     unionTag/removeTag full-set reasoning, and the "User XOR Tags"/
//     TagMeshMember-baseline design from the earlier gRPC-based version,
//     both carry over unchanged - see this file's own CreateMeshUser/
//     GrantStorageAccess doc comments for the "Bug fix" reasoning that
//     established that design, still accurate for the REST transport.
package headscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TagMeshMember is the permanent ACL tag NM-F-08 assigns to every node at
// mesh-join time (via the pre-auth key's AclTags), satisfying NM-F-13:
// membership alone, never Storage-Service reachability. This session's
// invented, documented literal - no SRS/design doc names a concrete tag
// string for mesh membership.
const TagMeshMember = "tag:mesh-member"

// TagStorageAccess is the ACL tag NM-F-09 assigns (in addition to
// TagMeshMember, never replacing it) to grant a node reachability toward
// Storage-Service for GrantDuration. This session's invented, documented
// literal, chosen to read naturally against Headscale's ACL policy
// (policy.mode: db, per this session's compose-file decision) - the real
// ACL policy document that references this literal is a deployment/
// NM-F-12/15 concern, out of this task's scope.
const TagStorageAccess = "tag:storage-access"

// GrantDuration is Network-Manager's own fixed grant window, per NM-F-09's
// literal "record an expiry 12 hours from that point" - Network-Manager
// owns this value; it is not taken from whatever duration a caller
// requests (see internal/httpapi's handler doc comment for the zero-trust
// reasoning, RNF-SEC-02/03).
const GrantDuration = 12 * time.Hour

// preAuthKeyExpiration is how long NM-F-08's generated pre-auth key stays
// valid before a client must have used it to join the mesh. SRS NM-F-08
// only says "short-lived", giving no concrete duration - this session's
// judgment call, chosen generously short relative to a human completing
// UC-01's registration flow and immediately configuring their Tailscale
// client, while still comfortably bounding the exposure window if a key
// is intercepted in transit. Revisit if a human/ops decision fixes a
// different value.
const preAuthKeyExpiration = 15 * time.Minute

// Node is this package's own minimal representation of a Headscale node,
// decoded from the REST API's JSON response (rest.go's restNode) -
// carries only the fields CreateMeshUser/GrantStorageAccess/RemoveNodeTag
// actually need. PreAuthKeyID is 0 for a node with no pre-auth key
// (Headscale's own IDs are positive, auto-incrementing - 0 never occurs
// for a real key), the same zero-value-means-absent convention the
// previous gRPC-based version relied on via v1.Node.GetPreAuthKey().GetId().
type Node struct {
	ID           uint64
	Tags         []string
	PreAuthKeyID uint64
}

// Service is the narrow REST-backed operation set CreateMeshUser/
// GrantStorageAccess/RemoveNodeTag need. *Client (rest.go, a real HTTP
// connection to Headscale's REST API through the reverse proxy) and a
// hand-written test fake both implement it - same "narrow interface +
// real/fake implementation" shape the gRPC-based version of this package
// used, just REST-shaped now.
type Service interface {
	// CreateUser creates a Headscale user with name/email, returning its
	// numeric ID.
	CreateUser(ctx context.Context, name, email string) (userID uint64, err error)
	// CreatePreAuthKey creates a single-use, non-ephemeral pre-auth key
	// for userID, tagged aclTags, expiring at expiration. Reusable/
	// Ephemeral are always false - NM-F-08's own business rule, not
	// exposed as parameters (see CreateMeshUser's own call site).
	CreatePreAuthKey(ctx context.Context, userID uint64, expiration time.Time, aclTags []string) (key string, keyID uint64, err error)
	// ListNodes returns every mesh node, tagged and user-owned alike (no
	// per-user filter) - see GrantStorageAccess's own doc comment for why
	// this package never filters by user.
	ListNodes(ctx context.Context) ([]Node, error)
	// SetTags replaces nodeID's entire tag set with tags (Headscale's own
	// semantics: a full replace, never a patch).
	SetTags(ctx context.Context, nodeID uint64, tags []string) error
	// GetNode fetches a single node's current state (RemoveNodeTag needs
	// its current tags before computing the new full set to SetTags).
	GetNode(ctx context.Context, nodeID uint64) (Node, error)
}

// meshUsername deterministically derives a Headscale-username-valid
// identifier from email: "u" (guarantees util.ValidateUsername's
// starts-with-a-letter rule regardless of what the hash produces) followed
// by 24 lowercase hex characters of SHA-256(lowercased email). Emails are
// lowercased first for the same reason hashing.HashEmail (DV-F-03)
// normalizes case: this function must be deterministic regardless of the
// casing a caller happens to submit. Deterministic (not random) so that a
// retried NM-F-08 call for the same email is idempotent. NM-F-09 no longer
// needs a Headscale username or user lookup of any kind at grant time (see
// GrantStorageAccess's own doc comment) - this function exists purely to
// give CreateUser a valid, deterministic Name.
func meshUsername(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return "u" + hex.EncodeToString(sum[:])[:24]
}

// CreateMeshUser implements NM-F-08: create a dedicated Headscale user for
// email and generate a short-lived pre-auth key for it, tagged
// TagMeshMember from the start (NM-F-13: membership only, no
// reachability). Returns the pre-auth key string the client uses to join
// the mesh (UC-01 step 7-8) - the only credential in this codebase that
// ever travels all the way back to the actual user - and the created key's
// numeric Headscale ID.
//
// The caller MUST persist the returned ID against email permanently (see
// internal/grants' mesh_users table, wired through internal/httpapi.
// Handler.MeshUsers) - GrantStorageAccess needs it at every future login
// to find this user's mesh node, since Headscale's own per-user node
// ownership cannot be used for that lookup (see GrantStorageAccess's own
// doc comment for why).
func CreateMeshUser(ctx context.Context, svc Service, email string) (key string, preAuthKeyID uint64, err error) {
	username := meshUsername(email)

	userID, err := svc.CreateUser(ctx, username, email)
	if err != nil {
		return "", 0, fmt.Errorf("%w: create user: %w", ErrHeadscaleRequestFailed, err)
	}

	expiration := time.Now().Add(preAuthKeyExpiration)

	key, keyID, err := svc.CreatePreAuthKey(ctx, userID, expiration, []string{TagMeshMember})
	if err != nil {
		return "", 0, fmt.Errorf("%w: create pre-auth key: %w", ErrHeadscaleRequestFailed, err)
	}
	if key == "" {
		return "", 0, fmt.Errorf("%w: create pre-auth key: empty key in response", ErrHeadscaleRequestFailed)
	}

	return key, keyID, nil
}

// GrantStorageAccess implements NM-F-09: given the Headscale pre-auth-key
// ID recorded for this user at registration time (NM-F-08, persisted by
// the caller - see CreateMeshUser's own doc comment), find that user's
// already-existing mesh node (UC-02/SRS 2.6: the node joined once, at
// registration, and persists across logins) and add TagStorageAccess to
// its tag set (alongside the TagMeshMember it already carries), granting
// reachability toward Storage-Service for GrantDuration.
//
// The node is found by scanning every mesh node (ListNodes, no per-user
// filter) for the one whose PreAuthKeyID equals preAuthKeyID - not by any
// per-user ownership lookup. Why: a node registered via a tagged pre-auth
// key (as every node this package's CreateMeshUser creates is) is owned
// by Headscale's synthetic "tagged-devices" pseudo-user, never by the
// specific per-user account CreateUser created ("User XOR Tags": once
// tagged, a node can never be converted back to user-owned) - confirmed
// live against a real Headscale instance in an earlier session (a
// per-user ListUsers/ListNodes(User:...) lookup returned zero nodes,
// 100% of the time, for exactly this reason). The pre-auth key's own
// numeric ID is preserved on every node that registered via one
// (Node.PreAuthKey.Id), regardless of tagged/user-owned status - metadata
// about how the node was created, unrelated to current ownership, so it
// cannot be broken by that dichotomy.
//
// GrantDuration is fixed by this package, not taken from a caller-supplied
// value - see the constant's own doc comment.
//
// Returns the granted node's Headscale node ID so a caller can persist it
// (NM-F-11: internal/grants.Store keys a grant by node ID + tag, needed by
// NM-F-10's sweep to call RevokeStorageAccess on the exact same node
// without repeating this lookup at sweep time). No expiry is persisted by
// this call itself - that remains the caller's responsibility (see
// internal/httpapi.Handler.Grant).
func GrantStorageAccess(ctx context.Context, svc Service, preAuthKeyID uint64) (uint64, error) {
	nodes, err := svc.ListNodes(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: list nodes: %w", ErrHeadscaleRequestFailed, err)
	}

	var node *Node
	for i := range nodes {
		if nodes[i].PreAuthKeyID == preAuthKeyID {
			node = &nodes[i]
			break
		}
	}
	if node == nil {
		return 0, fmt.Errorf("%w: no mesh node for this pre-auth key id", ErrMeshUserNotFound)
	}

	tags := unionTag(node.Tags, TagStorageAccess)

	if err := svc.SetTags(ctx, node.ID, tags); err != nil {
		return 0, fmt.Errorf("%w: set tags: %w", ErrHeadscaleRequestFailed, err)
	}

	return node.ID, nil
}

// RevokeStorageAccess implements NM-F-10's tag-removal half: remove
// TagStorageAccess from nodeID, leaving TagMeshMember (and any other tag
// the node carries) untouched. A thin, named wrapper over RemoveNodeTag so
// call sites (the sweep loop) read as "revoke the grant", not "remove this
// specific string".
func RevokeStorageAccess(ctx context.Context, svc Service, nodeID uint64) error {
	return RemoveNodeTag(ctx, svc, nodeID, TagStorageAccess)
}

// RemoveNodeTag removes tag from nodeID's tag set (NM-F-10's revoke path),
// fetching the node's current tags first since SetTags replaces the whole
// set, never patches it (same constraint unionTag/GrantStorageAccess
// already document). If tag is the node's only remaining tag, this call
// fails with ErrCannotRemoveLastTag instead of ever calling SetTags with
// an empty list - Headscale's own SetTags handler rejects that outright
// ("cannot remove all tags from a node"), and failing here first (RD-04,
// fail-secure) gives a caller a clearer, package-specific error than a raw
// HTTP failure would.
//
// A genuinely nonexistent nodeID surfaces as ErrHeadscaleRequestFailed
// (wrapping GetNode's own error), not ErrMeshUserNotFound - a shift from
// the earlier gRPC-based version, which could apparently observe a
// "successful" response carrying a nil Node for an unknown ID. Headscale's
// REST GetNode returns a real non-2xx status for an unknown node ID
// (confirmed by reading hscontrol/grpcv1.go's GetNode handler: it returns
// the error from db.GetNodeByID directly, which grpc-gateway then maps to
// a non-2xx HTTP status), so rest.go's Client.GetNode already turns that
// into an error before this function ever sees a node value at all - there
// is no successful-but-empty case left to distinguish.
func RemoveNodeTag(ctx context.Context, svc Service, nodeID uint64, tag string) error {
	node, err := svc.GetNode(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("%w: get node: %w", ErrHeadscaleRequestFailed, err)
	}

	remaining := removeTag(node.Tags, tag)
	if len(remaining) == 0 {
		return ErrCannotRemoveLastTag
	}

	if err := svc.SetTags(ctx, nodeID, remaining); err != nil {
		return fmt.Errorf("%w: set tags: %w", ErrHeadscaleRequestFailed, err)
	}

	return nil
}

// unionTag returns existing with tag appended if not already present -
// SetTags always receives the node's full desired tag set (it replaces,
// not patches, per Headscale's own semantics), so an already-granted node
// re-requesting a grant must not lose TagMeshMember or duplicate
// TagStorageAccess.
func unionTag(existing []string, tag string) []string {
	for _, t := range existing {
		if t == tag {
			return existing
		}
	}
	return append(append([]string{}, existing...), tag)
}

// removeTag returns existing with every occurrence of tag removed -
// RemoveNodeTag's counterpart to unionTag, same "SetTags replaces, never
// patches" reasoning.
func removeTag(existing []string, tag string) []string {
	out := make([]string, 0, len(existing))
	for _, t := range existing {
		if t != tag {
			out = append(out, t)
		}
	}
	return out
}
