// Package headscale is Network-Manager's thin wrapper over the real
// Headscale gRPC coordination API (github.com/juanfont/headscale/gen/go/
// headscale/v1), implementing NM-F-08 (mesh-user + pre-auth-key creation)
// and NM-F-09 (ACL-tag grant for reachability toward Storage-Service).
//
// API surface confirmed directly against github.com/juanfont/headscale
// v0.29.2 this session (go doc + reading hscontrol/grpcv1.go,
// hscontrol/util/dns.go, cmd/headscale/cli/utils.go - not merely trusted
// from a prior research summary, per that summary's own recommendation):
//
//   - Connection: a plain gRPC channel (grpc.NewClient), authenticated with
//     Headscale's own API key as a bearer token via
//     grpc.WithPerRPCCredentials, over TLS (grpc.credentials.NewTLS) -
//     confirmed from Headscale's own CLI (cmd/headscale/cli/utils.go's
//     tokenAuth type: GetRequestMetadata returns
//     {"authorization": "Bearer "+token}, RequireTransportSecurity() is
//     true, i.e. TLS is mandatory for this credential). This is a
//     different trust mechanism from every other inter-service call in
//     this codebase (pkg/mtls's mutual, organization-checked
//     certificates): Headscale's coordination API authenticates the
//     caller by a shared secret bearer token, not a client certificate.
//     Network-Manager's own HTTP boundary (internal/server,
//     internal/httpapi) still enforces NM-F-03's mTLS organization check
//     independently - this package is what Network-Manager calls *after*
//     that check has already passed, to reach a second, separate internal
//     dependency (Headscale), the same relationship Database-Vault has to
//     its own Postgres connection (no mTLS there either, a private
//     internal dependency, not a peer service under SRS 4.*'s mTLS rules).
//   - CreatePreAuthKeyRequest.Expiration must always be set explicitly: a
//     nil Expiration is passed to time.Time{} (Go's zero value) by
//     Headscale's own CreatePreAuthKey handler (hscontrol/grpcv1.go), which
//     is very likely then treated as "never expires" downstream - the real
//     bug flagged by the prior research memory (GitHub issues #1579/#2087).
//     Confirmed the *cause* by reading the handler; did not reproduce the
//     downstream "non-expiring key" behavior against a live server this
//     session (see stepca-style integration test's own scope note).
//   - Headscale usernames (CreateUserRequest.Name) are validated by
//     util.ValidateUsername: at least 2 characters, must start with a
//     unicode letter, and may contain only letters, digits, '-', '.', '_',
//     and at most one '@'. A raw email address technically satisfies this
//     for the common case (one '@', letters, dots) but not for the full
//     range of RFC 5322-valid emails this codebase's own pkg/validation
//     already accepts (e.g. '+' in the local part) - so this package does
//     NOT use the email as the Headscale username directly.
//   - CreateUserRequest carries a first-class Email field (confirmed via go
//     doc and hscontrol/grpcv1.go's ListUsers handler: passing Email routes
//     to ListUsersWithFilter(&types.User{Email: ...})) - NM-F-08 sets both
//     Name (a generated, always-username-valid identifier) and Email (the
//     real address) on the Headscale user it creates. NM-F-09 no longer
//     looks this user up at all, by Email or otherwise - see the corrected
//     "User XOR Tags" note below for why that lookup path was replaced.
//   - SetTags on a node is an "add a tag" operation only in the narrow
//     sense that Headscale's own SetTags handler rejects an empty tag
//     list outright ("cannot remove all tags from a node - tagged nodes
//     must have at least one tag", hscontrol/grpcv1.go) and documents
//     tagging as a one-way conversion for the node ("User XOR Tags: nodes
//     are either tagged or user-owned, never both ... once tagged, a node
//     cannot be converted back to user-owned"). Practical consequence for
//     this package's design, flagged clearly for NM-F-10 (the future
//     expiry-sweep requirement, out of that task's scope): the storage-
//     reachability tag can never be the node's *only* tag if a later
//     requirement needs to remove it again while leaving the node mesh-
//     joined. This package's NM-F-08 (CreateMeshUser) therefore assigns a
//     permanent baseline tag (TagMeshMember) to the pre-auth key itself
//     (CreatePreAuthKeyRequest.AclTags) - the node is "tagged" from the
//     moment it joins the mesh, but TagMeshMember alone grants no
//     Storage-Service reachability (NM-F-13: "the pre-auth key ... does
//     not, by itself, grant reachability"). NM-F-09 (GrantStorageAccess)
//     then adds TagStorageAccess to that node's existing tag set via
//     SetTags, so the set is always TagMeshMember plus (once granted)
//     TagStorageAccess - never empty, so a future NM-F-10 removing only
//     TagStorageAccess always leaves a valid, non-empty tag list behind.
//
// Bug fix (this session, verified live against a real Headscale instance -
// not hypothetical): a prior version of GrantStorageAccess found "this
// user's node" via lookupUserByEmail (ListUsers by Email) followed by
// ListNodes(User: <that username>). That NEVER worked, because
// CreatePreAuthKey above sets AclTags on the pre-auth key - and per
// Headscale's own "User XOR Tags" rule (quoted above), a node registering
// with a tagged pre-auth key becomes a TAGGED node, owned by Headscale's
// built-in synthetic "tagged-devices" pseudo-user, never by the specific
// per-user account CreateUser created. ListNodes(User: <real username>)
// therefore always returned zero nodes, and every login's grant step
// failed 100% of the time with ErrMeshUserNotFound - confirmed by joining
// a real Tailscale client to a real dev Headscale instance and observing
// `headscale nodes list` report the joined node's owner as
// "tagged-devices", not the per-user account.
//
// The fix stops relying on Headscale's per-user node ownership for this
// lookup entirely, correlating instead via the pre-auth key's own numeric
// ID (v1.PreAuthKey.Id), which Headscale preserves on every node that
// registered via a pre-auth key (Node.PreAuthKey.Id) regardless of
// tagged/user-owned status - it is metadata about how the node was
// created, unrelated to current ownership, so it cannot be broken by the
// tagged/user-owned dichotomy again. CreateMeshUser now returns the
// created pre-auth key's Id alongside its Key string; the caller
// (internal/httpapi.Handler, backed by internal/grants' new permanent
// email -> pre-auth-key-ID mapping) persists it and passes it back into
// GrantStorageAccess at every future login. GrantStorageAccess calls
// ListNodes with no User filter at all (confirmed via reading
// hscontrol/grpcv1.go's ListNodes handler: an empty/unset User field skips
// the per-user filter and returns every node, tagged and user-owned
// alike), then scans the results for the one node whose
// GetPreAuthKey().GetId() matches the stored ID.
package headscale

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
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
// NM-F-14/15 concern, out of this task's scope.
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

// Service is the narrow subset of Headscale's real gRPC API this package
// needs. github.com/juanfont/headscale/gen/go/headscale/v1.
// HeadscaleServiceClient is itself an interface (confirmed via go doc), so
// the *grpc.ClientConn-backed client v1.NewHeadscaleServiceClient returns
// already satisfies Service through Go's ordinary structural typing - no
// adapter type is needed, the same shape already used for paho's
// mqtt.Client in pkg/metrics (backing DV-F-16/17 and every other
// service's metrics publish).
// Tests substitute a hand-written fake, never a real Headscale server.
type Service interface {
	CreateUser(ctx context.Context, in *v1.CreateUserRequest, opts ...grpc.CallOption) (*v1.CreateUserResponse, error)
	CreatePreAuthKey(ctx context.Context, in *v1.CreatePreAuthKeyRequest, opts ...grpc.CallOption) (*v1.CreatePreAuthKeyResponse, error)
	ListNodes(ctx context.Context, in *v1.ListNodesRequest, opts ...grpc.CallOption) (*v1.ListNodesResponse, error)
	SetTags(ctx context.Context, in *v1.SetTagsRequest, opts ...grpc.CallOption) (*v1.SetTagsResponse, error)
	// GetNode is added for NM-F-10 (the expiry sweep needs to read a
	// node's current tag set before removing one) - neither of
	// NM-F-08/NM-F-09's original handlers needed it.
	GetNode(ctx context.Context, in *v1.GetNodeRequest, opts ...grpc.CallOption) (*v1.GetNodeResponse, error)
}

// tokenAuth implements grpc/credentials.PerRPCCredentials, carrying
// Headscale's API key as a bearer token on every RPC. Shape confirmed
// directly against Headscale's own CLI source
// (cmd/headscale/cli/utils.go's identically-named unexported type).
type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + t.token}, nil
}

func (tokenAuth) RequireTransportSecurity() bool { return true }

// Dial connects to Headscale's gRPC coordination endpoint at address
// (NM-F-14: reachable only from the private network - this dial is made
// from within it), authenticating with apiKey. tlsConfig configures the
// transport; callers running against a self-signed/dev Headscale
// deployment set InsecureSkipVerify there themselves - this package makes
// no such decision on a caller's behalf.
func Dial(address, apiKey string, tlsConfig *tls.Config) (*grpc.ClientConn, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(tokenAuth{token: apiKey}),
	)
	if err != nil {
		return nil, fmt.Errorf("headscale: dial %s: %w", address, err)
	}

	return conn, nil
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
// the package doc comment's "Bug fix" section) - this function exists
// purely to give CreateUser a valid, deterministic Name.
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
// numeric Headscale ID (v1.PreAuthKey.Id).
//
// The caller MUST persist the returned ID against email permanently (see
// internal/grants' mesh_users table, wired through internal/httpapi.
// Handler.MeshUsers) - GrantStorageAccess needs it at every future login
// to find this user's mesh node, since Headscale's own per-user node
// ownership cannot be used for that lookup (see the package doc comment's
// "Bug fix" section for why).
func CreateMeshUser(ctx context.Context, svc Service, email string) (key string, preAuthKeyID uint64, err error) {
	username := meshUsername(email)

	if _, err := svc.CreateUser(ctx, &v1.CreateUserRequest{
		Name:  username,
		Email: email,
	}); err != nil {
		return "", 0, fmt.Errorf("%w: create user: %w", ErrHeadscaleRequestFailed, err)
	}

	expiration := timestamppb.New(time.Now().Add(preAuthKeyExpiration))

	resp, err := svc.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{
		Reusable:   false,
		Ephemeral:  false,
		Expiration: expiration,
		AclTags:    []string{TagMeshMember},
	})
	if err != nil {
		return "", 0, fmt.Errorf("%w: create pre-auth key: %w", ErrHeadscaleRequestFailed, err)
	}
	if resp.GetPreAuthKey() == nil || resp.GetPreAuthKey().GetKey() == "" {
		return "", 0, fmt.Errorf("%w: create pre-auth key: empty key in response", ErrHeadscaleRequestFailed)
	}

	return resp.GetPreAuthKey().GetKey(), resp.GetPreAuthKey().GetId(), nil
}

// GrantStorageAccess implements NM-F-09: given the Headscale pre-auth-key
// ID recorded for this user at registration time (NM-F-08, persisted by
// the caller - see CreateMeshUser's own doc comment), find that user's
// already-existing mesh node (UC-02/SRS 2.6: the node joined once, at
// registration, and persists across logins) and add TagStorageAccess to
// its tag set (alongside the TagMeshMember it already carries), granting
// reachability toward Storage-Service for GrantDuration.
//
// The node is found by scanning every mesh node (ListNodes with no User
// filter - Headscale's own ListNodes handler skips the per-user filter
// entirely when User is unset, confirmed by reading
// hscontrol/grpcv1.go) for the one whose GetPreAuthKey().GetId() equals
// preAuthKeyID - not by any per-user ownership lookup. See the package
// doc comment's "Bug fix" section for why: a node registered via a
// tagged pre-auth key (as every node created by this package's
// CreateMeshUser is) is owned by Headscale's synthetic "tagged-devices"
// pseudo-user, never by the specific per-user account CreateUser
// created, so a per-user ListNodes/ListUsers lookup can never find it.
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
	nodes, err := svc.ListNodes(ctx, &v1.ListNodesRequest{})
	if err != nil {
		return 0, fmt.Errorf("%w: list nodes: %w", ErrHeadscaleRequestFailed, err)
	}

	var node *v1.Node
	for _, n := range nodes.GetNodes() {
		if n.GetPreAuthKey().GetId() == preAuthKeyID {
			node = n
			break
		}
	}
	if node == nil {
		return 0, fmt.Errorf("%w: no mesh node for this pre-auth key id", ErrMeshUserNotFound)
	}

	tags := unionTag(node.GetTags(), TagStorageAccess)

	if _, err := svc.SetTags(ctx, &v1.SetTagsRequest{
		NodeId: node.GetId(),
		Tags:   tags,
	}); err != nil {
		return 0, fmt.Errorf("%w: set tags: %w", ErrHeadscaleRequestFailed, err)
	}

	return node.GetId(), nil
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
// set, never patches
// it (same constraint unionTag/GrantStorageAccess already document). If
// tag is the node's only remaining tag, this call fails with
// ErrCannotRemoveLastTag instead of ever calling SetTags with an empty
// list - Headscale's own SetTags handler rejects that outright ("cannot
// remove all tags from a node"), and failing here first (RD-04,
// fail-secure) gives a caller a clearer, package-specific error than a raw
// gRPC failure would.
func RemoveNodeTag(ctx context.Context, svc Service, nodeID uint64, tag string) error {
	resp, err := svc.GetNode(ctx, &v1.GetNodeRequest{NodeId: nodeID})
	if err != nil {
		return fmt.Errorf("%w: get node: %w", ErrHeadscaleRequestFailed, err)
	}
	if resp.GetNode() == nil {
		return fmt.Errorf("%w: node %d not found", ErrMeshUserNotFound, nodeID)
	}

	remaining := removeTag(resp.GetNode().GetTags(), tag)
	if len(remaining) == 0 {
		return ErrCannotRemoveLastTag
	}

	if _, err := svc.SetTags(ctx, &v1.SetTagsRequest{
		NodeId: nodeID,
		Tags:   remaining,
	}); err != nil {
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
