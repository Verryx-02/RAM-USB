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
//   - CreateUserRequest/ListUsersRequest both carry a first-class Email
//     field (confirmed via go doc and hscontrol/grpcv1.go's ListUsers
//     handler: passing Email routes to ListUsersWithFilter(&types.User{
//     Email: ...})). This resolves the identifier-reconciliation question
//     the task flagged: NM-F-08 sets both Name (a generated,
//     always-username-valid identifier) and Email (the real address) on
//     the Headscale user it creates; NM-F-09 looks the user up by Email
//     via ListUsers, never by reconstructing a username from the email.
//   - SetTags on a node is an "add a tag" operation only in the narrow
//     sense that Headscale's own SetTags handler rejects an empty tag
//     list outright ("cannot remove all tags from a node - tagged nodes
//     must have at least one tag", hscontrol/grpcv1.go) and documents
//     tagging as a one-way conversion for the node ("User XOR Tags: nodes
//     are either tagged or user-owned, never both ... once tagged, a node
//     cannot be converted back to user-owned"). Practical consequence for
//     this package's design, flagged clearly for NM-F-10 (the future
//     expiry-sweep requirement, out of this task's scope): the storage-
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
// mqtt.Client in services/database-vault/internal/metrics (DV-F-16/17).
// Tests substitute a hand-written fake, never a real Headscale server.
type Service interface {
	CreateUser(ctx context.Context, in *v1.CreateUserRequest, opts ...grpc.CallOption) (*v1.CreateUserResponse, error)
	ListUsers(ctx context.Context, in *v1.ListUsersRequest, opts ...grpc.CallOption) (*v1.ListUsersResponse, error)
	CreatePreAuthKey(ctx context.Context, in *v1.CreatePreAuthKeyRequest, opts ...grpc.CallOption) (*v1.CreatePreAuthKeyResponse, error)
	ListNodes(ctx context.Context, in *v1.ListNodesRequest, opts ...grpc.CallOption) (*v1.ListNodesResponse, error)
	SetTags(ctx context.Context, in *v1.SetTagsRequest, opts ...grpc.CallOption) (*v1.SetTagsResponse, error)
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
// retried NM-F-08 call for the same email is idempotent, and so a
// completely independent lookup path is never required - though this
// package's own NM-F-09 lookup in fact goes through Headscale's native
// Email field instead (see the package doc comment), not through
// recomputing this function.
func meshUsername(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return "u" + hex.EncodeToString(sum[:])[:24]
}

// CreateMeshUser implements NM-F-08: create a dedicated Headscale user for
// email and generate a short-lived pre-auth key for it, tagged
// TagMeshMember from the start (NM-F-13: membership only, no
// reachability). Returns the pre-auth key string the client uses to join
// the mesh (UC-01 step 7-8) - the only credential in this codebase that
// ever travels all the way back to the actual user.
func CreateMeshUser(ctx context.Context, svc Service, email string) (string, error) {
	username := meshUsername(email)

	if _, err := svc.CreateUser(ctx, &v1.CreateUserRequest{
		Name:  username,
		Email: email,
	}); err != nil {
		return "", fmt.Errorf("%w: create user: %v", ErrHeadscaleRequestFailed, err)
	}

	expiration := timestamppb.New(time.Now().Add(preAuthKeyExpiration))

	resp, err := svc.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{
		Reusable:   false,
		Ephemeral:  false,
		Expiration: expiration,
		AclTags:    []string{TagMeshMember},
	})
	if err != nil {
		return "", fmt.Errorf("%w: create pre-auth key: %v", ErrHeadscaleRequestFailed, err)
	}
	if resp.GetPreAuthKey() == nil || resp.GetPreAuthKey().GetKey() == "" {
		return "", fmt.Errorf("%w: create pre-auth key: empty key in response", ErrHeadscaleRequestFailed)
	}

	return resp.GetPreAuthKey().GetKey(), nil
}

// GrantStorageAccess implements NM-F-09: look up the Headscale user
// created for email at registration time (NM-F-08), find its
// already-existing mesh node (UC-02/SRS 2.6: the node joined once, at
// registration, and persists across logins), and add TagStorageAccess to
// its tag set (alongside the TagMeshMember it already carries), granting
// reachability toward Storage-Service for GrantDuration.
//
// GrantDuration is fixed by this package, not taken from a caller-supplied
// value - see the constant's own doc comment.
//
// No expiry is persisted by this call (NM-F-11, out of this task's
// scope): a caller wanting the 12-hour window actually enforced later
// (NM-F-10) must record it themselves for now.
func GrantStorageAccess(ctx context.Context, svc Service, email string) error {
	users, err := svc.ListUsers(ctx, &v1.ListUsersRequest{Email: email})
	if err != nil {
		return fmt.Errorf("%w: list users: %v", ErrHeadscaleRequestFailed, err)
	}
	if len(users.GetUsers()) == 0 {
		return fmt.Errorf("%w: no headscale user for this email", ErrMeshUserNotFound)
	}
	// Headscale's own ListUsersWithFilter(Email:...) is an equality
	// filter, not fuzzy matching - more than one result would mean two
	// Headscale users share an email, which NM-F-08 never creates
	// deliberately. Treat it the same as "not found" (RD-04, fail-secure)
	// rather than guessing which one is the real account.
	if len(users.GetUsers()) > 1 {
		return fmt.Errorf("%w: multiple headscale users share this email", ErrMeshUserNotFound)
	}
	username := users.GetUsers()[0].GetName()

	nodes, err := svc.ListNodes(ctx, &v1.ListNodesRequest{User: username})
	if err != nil {
		return fmt.Errorf("%w: list nodes: %v", ErrHeadscaleRequestFailed, err)
	}
	if len(nodes.GetNodes()) == 0 {
		return fmt.Errorf("%w: no mesh node for this user", ErrMeshUserNotFound)
	}

	node := nodes.GetNodes()[0]
	tags := unionTag(node.GetTags(), TagStorageAccess)

	if _, err := svc.SetTags(ctx, &v1.SetTagsRequest{
		NodeId: node.GetId(),
		Tags:   tags,
	}); err != nil {
		return fmt.Errorf("%w: set tags: %v", ErrHeadscaleRequestFailed, err)
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
