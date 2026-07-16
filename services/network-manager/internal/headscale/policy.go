package headscale

import (
	"context"
	"encoding/json"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
)

// This file implements NM-F-01, NM-F-02, NM-F-04, NM-F-05, NM-F-06, and
// NM-F-07: the static mesh-reachability rules restricting which components
// may contact which others, translated from
// docs/design/diagrams/09-security-trust-zones.puml into a real Headscale
// ACL policy document pushed via the gRPC SetPolicy call (available
// because deployments' network-manager-headscale config sets
// policy.mode: database - see client.go's package doc comment for why that
// mode was chosen). Unlike NM-F-08/NM-F-09 (per-request, dynamic tag
// assignment on an individual node), these six rules are static for the
// lifetime of the deployment, so PushPolicy is meant to be called once at
// Network-Manager startup, not per request.
//
// Schema confirmed empirically against a real headscale/headscale:0.29
// container this session (docker compose's network-manager-headscale
// service, policy.mode: database), not merely inferred from reading
// source:
//   - "headscale policy check -f <file>" against a hand-written candidate
//     document confirmed the exact JSON shape (top-level "groups"/
//     "tagOwners"/"acls", each ACL entry "action"/"src"/"dst", a
//     "tag:x:*" suffix on every dst entry for "any port") before any Go
//     code was written.
//   - A throwaway SetPolicy/GetPolicy gRPC round trip against the same
//     live container (go doc github.com/juanfont/headscale/gen/go/
//     headscale/v1 confirmed SetPolicyRequest{Policy string}/
//     SetPolicyResponse{Policy string, UpdatedAt}) confirmed the policy
//     Headscale returns from GetPolicy afterward is byte-for-byte the
//     document that was pushed.
//   - Reading github.com/juanfont/headscale@v0.29.2's hscontrol/policy/v2
//     package (not imported - see policyDocument's own doc comment for
//     why) confirmed every "tag:" literal referenced by an ACL's src/dst
//     must also appear as a tagOwners key, or SetPolicy rejects the whole
//     document (Policy.validate's TagOwners.Contains check, "tag not
//     defined"). This is why this file also declares a tagOwners section
//     even though no rule here is about who may self-assign a tag - every
//     tag this system's nodes ever carry is assigned by Network-Manager
//     itself via CreatePreAuthKey's AclTags or SetTags (see NM-F-08/
//     NM-F-09 in client.go), never by an end user requesting to tag their
//     own device, so the tagOwners entries exist purely to satisfy this
//     structural validation rule, not to grant any real self-tagging
//     capability to policyAdminOwner.
//   - Headscale's Groups value type requires each entry to look like an
//     email address ("username must contain @": confirmed by the same
//     "headscale policy check" run rejecting a bare "network-manager-
//     admin" group member) - policyAdminOwner therefore has this shape,
//     it is not a real registered Headscale user email (no login ever
//     happens as this identity; see the point above).

// Tags identifying each internal component's mesh node, used as ACL src/
// dst selectors. TagMeshMember and TagStorageAccess (defined in client.go
// for NM-F-08/NM-F-09) identify a User's node's state, not a service - the
// two families are deliberately kept in the same package's tag vocabulary
// but never confused: services get exactly one of these six tags,
// User nodes get TagMeshMember and, once granted, TagStorageAccess, never
// one of these six.
//
// Literal strings are this session's invented, documented choice (no SRS/
// design doc names a concrete tag string for a service's own mesh
// identity) - chosen to read naturally alongside TagMeshMember/
// TagStorageAccess's existing "tag:kebab-case" convention.
const (
	TagEntryHub             = "tag:entry-hub"
	TagSecuritySwitch       = "tag:security-switch"
	TagDatabaseVault        = "tag:database-vault"
	TagStorageService       = "tag:storage-service"
	TagNetworkManager       = "tag:network-manager"
	TagCertificateAuthority = "tag:certificate-authority"
)

// policyAdminGroup/policyAdminOwner exist solely to give every tag
// referenced below a syntactically valid tagOwners entry - see this file's
// package-level doc comment for why their membership carries no real
// operational meaning in this system.
const (
	policyAdminGroup = "group:network-manager-admin"
	policyAdminOwner = "network-manager-admin@ram-usb.internal"
)

// allTags lists every tag this policy document's tagOwners section must
// cover: the six service tags declared in this file, plus the two User-
// node tags declared in client.go (TagMeshMember/TagStorageAccess) since
// NM-F-06/NM-F-07's rules reference them as ACL sources too.
var allTags = []string{
	TagEntryHub,
	TagSecuritySwitch,
	TagDatabaseVault,
	TagStorageService,
	TagNetworkManager,
	TagCertificateAuthority,
	TagMeshMember,
	TagStorageAccess,
}

// policyDocument is this package's own minimal Go representation of the
// subset of Headscale's ACL policy JSON schema this file needs (groups,
// tagOwners, one "accept" ACL rule shape). It deliberately does NOT import
// github.com/juanfont/headscale/hscontrol/policy/v2 (the real, much
// larger schema type Headscale's own server uses to parse and validate
// this same document): that package is Headscale's internal server-side
// implementation, not a published client API, pulls in a large graph of
// Tailscale-internal packages this client-side package has no other need
// for, and offers no version-compatibility guarantee to an external
// caller. encoding/json marshaling of a small local struct is sufficient -
// Headscale's SetPolicy re-parses and validates the resulting bytes on
// its own side regardless of how this package produced them, exactly the
// verification this file's PushPolicy/PushPolicy tests perform.
type policyDocument struct {
	Groups    map[string][]string `json:"groups"`
	TagOwners map[string][]string `json:"tagOwners"`
	ACLs      []policyACL         `json:"acls"`
}

// policyACL is one "accept" reachability rule: every node matching one of
// Src may contact every node matching one of Dst. Dst entries carry an
// explicit ":*" (any port) suffix, matching every rule this file builds -
// NM-F-01 through NM-F-07 are about *whether a component may be
// contacted at all*, not about restricting individual ports, and no SRS
// requirement names a port number for any internal service.
type policyACL struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// dstAny formats tag as an ACL destination alias with the wildcard port
// suffix Headscale's schema requires (confirmed via the live "headscale
// policy check" run documented in this file's package comment).
func dstAny(tag string) string {
	return tag + ":*"
}

// buildACLs returns the ordered list of ACL rules this file exists to
// produce. Each rule is traceable to exactly one requirement ID via its
// own comment; NM-F-04's "both directions" wording produces two rules,
// not one.
//
// A seventh rule, labeled NM-F-03, is included even though this task's
// scope named only NM-F-01/02/04/05/06/07: NM-F-03 ("only Security-Switch
// and Certificate-Authority can contact Network-Manager") is already
// implemented at the mTLS/HTTP boundary (internal/server, NM-F-03's own
// commit), and SS-F-05/NM-F-08/NM-F-09's already-shipped, already-tested
// traffic (Security-Switch calling Network-Manager to request a mesh
// user or a storage-access grant) depends on that path being reachable
// at the network layer too. Once any ACL rule exists in a Headscale
// policy, reachability not explicitly listed is denied by default - so
// omitting NM-F-03 here would silently break that already-built feature
// the moment this policy is pushed. This is flagged explicitly, not a
// silent scope expansion: confirm with the requirement owner if a
// different resolution is wanted.
func buildACLs() []policyACL {
	return []policyACL{
		{ // NM-F-01: only Entry-Hub, Database-Vault, Network-Manager, and
			// Certificate-Authority can contact Security-Switch.
			Action: "accept",
			Src:    []string{TagEntryHub, TagDatabaseVault, TagNetworkManager, TagCertificateAuthority},
			Dst:    []string{dstAny(TagSecuritySwitch)},
		},
		{ // NM-F-02: only Security-Switch, Storage-Service, and
			// Certificate-Authority can contact Database-Vault.
			Action: "accept",
			Src:    []string{TagSecuritySwitch, TagStorageService, TagCertificateAuthority},
			Dst:    []string{dstAny(TagDatabaseVault)},
		},
		{ // NM-F-03 (already implemented at the mTLS boundary; included
			// here so the network layer does not block it - see this
			// function's own doc comment): only Security-Switch and
			// Certificate-Authority can contact Network-Manager.
			Action: "accept",
			Src:    []string{TagSecuritySwitch, TagCertificateAuthority},
			Dst:    []string{dstAny(TagNetworkManager)},
		},
		{ // NM-F-04, direction one: every internal component can contact
			// Certificate-Authority.
			Action: "accept",
			Src:    []string{TagEntryHub, TagSecuritySwitch, TagDatabaseVault, TagStorageService, TagNetworkManager},
			Dst:    []string{dstAny(TagCertificateAuthority)},
		},
		{ // NM-F-04, direction two: Certificate-Authority can contact
			// every internal component.
			Action: "accept",
			Src:    []string{TagCertificateAuthority},
			Dst: []string{
				dstAny(TagEntryHub),
				dstAny(TagSecuritySwitch),
				dstAny(TagDatabaseVault),
				dstAny(TagStorageService),
				dstAny(TagNetworkManager),
			},
		},
		{ // NM-F-05 and (together with the rule below) half of NM-F-07:
			// only authenticated Users - nodes holding TagStorageAccess,
			// assigned by GrantStorageAccess/NM-F-09 - can contact
			// Storage-Service.
			Action: "accept",
			Src:    []string{TagStorageAccess},
			Dst:    []string{dstAny(TagStorageService)},
		},
		{ // NM-F-06 and (together with the rule above) the other half of
			// NM-F-07: every registered User - every node holding
			// TagMeshMember, assigned at mesh-join time by
			// CreateMeshUser/NM-F-08, which an authenticated User's node
			// still carries alongside TagStorageAccess - can contact
			// Entry-Hub.
			Action: "accept",
			Src:    []string{TagMeshMember},
			Dst:    []string{dstAny(TagEntryHub)},
		},
	}
}

// buildTagOwners returns the tagOwners section covering every tag
// buildACLs references (see allTags and this file's package doc comment
// for why every entry maps to the same placeholder owner).
func buildTagOwners() map[string][]string {
	owners := make(map[string][]string, len(allTags))
	for _, tag := range allTags {
		owners[tag] = []string{policyAdminGroup}
	}
	return owners
}

// PolicyDocument returns the marshaled JSON this package pushes to
// Headscale via PushPolicy. Exported so a unit test can decode it and
// assert its exact content without needing a live Headscale connection.
func PolicyDocument() ([]byte, error) {
	doc := policyDocument{
		Groups:    map[string][]string{policyAdminGroup: {policyAdminOwner}},
		TagOwners: buildTagOwners(),
		ACLs:      buildACLs(),
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("headscale: marshal policy document: %w", err)
	}
	return data, nil
}

// PolicyPusher is the narrow subset of Headscale's gRPC API PushPolicy
// needs - SetPolicy to push the document, GetPolicy for a caller wanting
// to confirm what is currently active. v1.NewHeadscaleServiceClient's
// result already satisfies this through Go's ordinary structural typing,
// same pattern as the Service interface above.
type PolicyPusher interface {
	SetPolicy(ctx context.Context, in *v1.SetPolicyRequest, opts ...grpc.CallOption) (*v1.SetPolicyResponse, error)
	GetPolicy(ctx context.Context, in *v1.GetPolicyRequest, opts ...grpc.CallOption) (*v1.GetPolicyResponse, error)
}

// PushPolicy implements NM-F-01/02/04/05/06/07 (plus NM-F-03, see
// buildACLs' doc comment): push this package's static ACL policy document
// to Headscale via SetPolicy. Meant to be called once, at Network-Manager
// startup - these rules do not change per request, unlike NM-F-08/NM-F-09's
// dynamic per-user tag assignment.
func PushPolicy(ctx context.Context, svc PolicyPusher) error {
	doc, err := PolicyDocument()
	if err != nil {
		return err
	}

	if _, err := svc.SetPolicy(ctx, &v1.SetPolicyRequest{Policy: string(doc)}); err != nil {
		return fmt.Errorf("%w: set policy: %v", ErrHeadscaleRequestFailed, err)
	}

	return nil
}
