package headscale

import (
	"context"
	"errors"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/grpc"
)

// fakeService is a hand-written fake of Service (CONTRIBUTING.md §7.5,
// docs/Test_Plan.md §2.1: table-driven unit tests use hand-written fakes,
// no real Headscale server).
type fakeService struct {
	createUserErr error
	gotCreateUser *v1.CreateUserRequest

	createPreAuthKeyResp *v1.CreatePreAuthKeyResponse
	createPreAuthKeyErr  error
	gotCreatePreAuthKey  *v1.CreatePreAuthKeyRequest

	listNodesResp *v1.ListNodesResponse
	listNodesErr  error

	setTagsErr error
	gotSetTags *v1.SetTagsRequest

	getNodeResp *v1.GetNodeResponse
	getNodeErr  error
	gotGetNode  *v1.GetNodeRequest
}

func (f *fakeService) CreateUser(_ context.Context, in *v1.CreateUserRequest, _ ...grpc.CallOption) (*v1.CreateUserResponse, error) {
	f.gotCreateUser = in
	if f.createUserErr != nil {
		return nil, f.createUserErr
	}
	return &v1.CreateUserResponse{User: &v1.User{Name: in.GetName(), Email: in.GetEmail()}}, nil
}

func (f *fakeService) CreatePreAuthKey(_ context.Context, in *v1.CreatePreAuthKeyRequest, _ ...grpc.CallOption) (*v1.CreatePreAuthKeyResponse, error) {
	f.gotCreatePreAuthKey = in
	if f.createPreAuthKeyErr != nil {
		return nil, f.createPreAuthKeyErr
	}
	return f.createPreAuthKeyResp, nil
}

func (f *fakeService) ListNodes(_ context.Context, _ *v1.ListNodesRequest, _ ...grpc.CallOption) (*v1.ListNodesResponse, error) {
	if f.listNodesErr != nil {
		return nil, f.listNodesErr
	}
	return f.listNodesResp, nil
}

func (f *fakeService) SetTags(_ context.Context, in *v1.SetTagsRequest, _ ...grpc.CallOption) (*v1.SetTagsResponse, error) {
	f.gotSetTags = in
	if f.setTagsErr != nil {
		return nil, f.setTagsErr
	}
	return &v1.SetTagsResponse{Node: &v1.Node{Id: in.GetNodeId(), Tags: in.GetTags()}}, nil
}

func (f *fakeService) GetNode(_ context.Context, in *v1.GetNodeRequest, _ ...grpc.CallOption) (*v1.GetNodeResponse, error) {
	f.gotGetNode = in
	if f.getNodeErr != nil {
		return nil, f.getNodeErr
	}
	return f.getNodeResp, nil
}

// Requirement: NM-F-08
func TestCreateMeshUser(t *testing.T) {
	tests := []struct {
		name                string
		createUserErr       error
		createPreAuthKeyErr error
		preAuthKeyResp      *v1.CreatePreAuthKeyResponse
		wantKey             string
		wantKeyID           uint64
		wantErr             error
	}{
		{
			name:           "success returns the generated pre-auth key and its numeric id",
			preAuthKeyResp: &v1.CreatePreAuthKeyResponse{PreAuthKey: &v1.PreAuthKey{Key: "authkey-abc123", Id: 42}},
			wantKey:        "authkey-abc123",
			wantKeyID:      42,
		},
		{
			name:          "CreateUser failure is wrapped in ErrHeadscaleRequestFailed",
			createUserErr: errors.New("boom"),
			wantErr:       ErrHeadscaleRequestFailed,
		},
		{
			name:                "CreatePreAuthKey failure is wrapped in ErrHeadscaleRequestFailed",
			createPreAuthKeyErr: errors.New("boom"),
			wantErr:             ErrHeadscaleRequestFailed,
		},
		{
			name:           "empty key in response is treated as a failure",
			preAuthKeyResp: &v1.CreatePreAuthKeyResponse{PreAuthKey: &v1.PreAuthKey{Key: ""}},
			wantErr:        ErrHeadscaleRequestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeService{
				createUserErr:        tt.createUserErr,
				createPreAuthKeyErr:  tt.createPreAuthKeyErr,
				createPreAuthKeyResp: tt.preAuthKeyResp,
			}

			key, keyID, err := CreateMeshUser(context.Background(), fake, "User@Example.com")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("CreateMeshUser() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateMeshUser() unexpected error = %v", err)
			}
			if key != tt.wantKey {
				t.Fatalf("CreateMeshUser() key = %q, want %q", key, tt.wantKey)
			}
			if keyID != tt.wantKeyID {
				t.Fatalf("CreateMeshUser() keyID = %d, want %d", keyID, tt.wantKeyID)
			}

			// NM-F-13: the pre-auth key is created with only the
			// permanent membership tag, never the reachability tag.
			if got := fake.gotCreatePreAuthKey.GetAclTags(); len(got) != 1 || got[0] != TagMeshMember {
				t.Fatalf("CreatePreAuthKey AclTags = %v, want [%s]", got, TagMeshMember)
			}
			if fake.gotCreatePreAuthKey.GetExpiration() == nil {
				t.Fatal("CreatePreAuthKey Expiration = nil, want an explicit deadline (the flagged omitted-expiration bug)")
			}
			if fake.gotCreatePreAuthKey.GetReusable() {
				t.Fatal("CreatePreAuthKey Reusable = true, want false (single registration, single use)")
			}

			// The generated username must be deterministic and
			// case-insensitive w.r.t. the email (mirrors DV-F-03's
			// hashing.HashEmail normalization rationale), and the
			// native Email field must carry the real address (still
			// useful for a human operator inspecting Headscale
			// directly, even though NM-F-09 no longer looks the user
			// up by it - see the package doc comment's "Bug fix"
			// section).
			if fake.gotCreateUser.GetEmail() != "User@Example.com" {
				t.Fatalf("CreateUser Email = %q, want the exact caller-supplied email", fake.gotCreateUser.GetEmail())
			}
			if got := meshUsername("User@Example.com"); got != meshUsername("user@example.com") {
				t.Fatalf("meshUsername is not case-insensitive: %q != %q", got, meshUsername("user@example.com"))
			}
			if fake.gotCreateUser.GetName() != meshUsername("User@Example.com") {
				t.Fatalf("CreateUser Name = %q, want %q", fake.gotCreateUser.GetName(), meshUsername("User@Example.com"))
			}
		})
	}
}

// Requirement: NM-F-08
func TestMeshUsername_AlwaysValid(t *testing.T) {
	// A generated username must always satisfy Headscale's own
	// util.ValidateUsername rule (confirmed via reading
	// hscontrol/util/dns.go this session): >= 2 chars, starts with a
	// letter, only letters/digits/'-'/'.'/'_'/at most one '@'.
	emails := []string{
		"user@example.com",
		"a+tag@example.co.uk",
		"",
		"weird!chars#here@example.com",
	}
	for _, email := range emails {
		name := meshUsername(email)
		if len(name) < 2 {
			t.Fatalf("meshUsername(%q) = %q, too short", email, name)
		}
		if name[0] < 'a' || name[0] > 'z' {
			t.Fatalf("meshUsername(%q) = %q, does not start with a letter", email, name)
		}
		for _, c := range name {
			isLetter := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLetter && !isDigit {
				t.Fatalf("meshUsername(%q) = %q, contains invalid character %q", email, name, c)
			}
		}
	}
}

// Requirement: NM-F-09
func TestGrantStorageAccess(t *testing.T) {
	tests := []struct {
		name              string
		preAuthKeyID      uint64
		listNodesResp     *v1.ListNodesResponse
		listNodesErr      error
		setTagsErr        error
		wantErr           error
		wantTags          []string
		wantNodeID        uint64
		wantSetTagsNodeID uint64
	}{
		{
			name:         "success adds TagStorageAccess alongside the existing TagMeshMember",
			preAuthKeyID: 100,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 100}},
			}},
			wantTags:          []string{TagMeshMember, TagStorageAccess},
			wantNodeID:        42,
			wantSetTagsNodeID: 42,
		},
		{
			name:         "already-granted node is not given a duplicate tag",
			preAuthKeyID: 100,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember, TagStorageAccess}, PreAuthKey: &v1.PreAuthKey{Id: 100}},
			}},
			wantTags:          []string{TagMeshMember, TagStorageAccess},
			wantNodeID:        42,
			wantSetTagsNodeID: 42,
		},
		{
			// This is the actual proof this session's live-reproduced
			// bug is fixed: several other users' nodes are also on the
			// mesh, each with its own distinct PreAuthKey.Id (none of
			// them owned by a "user" this package's now-removed
			// per-user ListUsers/ListNodes(User:...) lookup could ever
			// have matched anyway, since every node here is tagged, not
			// user-owned). GrantStorageAccess must select the ONE node
			// whose PreAuthKey.Id equals the caller-supplied
			// preAuthKeyID - not the first node in the list, not a
			// random one.
			name:         "selects the one node whose pre-auth key id matches, among several other users' nodes",
			preAuthKeyID: 200,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 10, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 100}},
				{Id: 20, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 200}},
				{Id: 30, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 300}},
			}},
			wantTags:          []string{TagMeshMember, TagStorageAccess},
			wantNodeID:        20,
			wantSetTagsNodeID: 20,
		},
		{
			// RD-04, fail-secure: the caller's client never actually
			// joined the mesh with the pre-auth key NM-F-08 generated
			// (a real, correct failure case, not an edge case) - other
			// users' nodes exist, but none carries this preAuthKeyID.
			name:         "no mesh node for this pre-auth key id is a fail-secure ErrMeshUserNotFound",
			preAuthKeyID: 999,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 10, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 100}},
				{Id: 20, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 200}},
			}},
			wantErr: ErrMeshUserNotFound,
		},
		{
			name:          "empty node list is a fail-secure ErrMeshUserNotFound",
			preAuthKeyID:  100,
			listNodesResp: &v1.ListNodesResponse{Nodes: nil},
			wantErr:       ErrMeshUserNotFound,
		},
		{
			name:         "a node with no pre-auth key at all never matches",
			preAuthKeyID: 100,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 10, Tags: []string{TagMeshMember}, PreAuthKey: nil},
			}},
			wantErr: ErrMeshUserNotFound,
		},
		{
			name:         "ListNodes failure is wrapped in ErrHeadscaleRequestFailed",
			preAuthKeyID: 100,
			listNodesErr: errors.New("boom"),
			wantErr:      ErrHeadscaleRequestFailed,
		},
		{
			name:         "SetTags failure is wrapped in ErrHeadscaleRequestFailed",
			preAuthKeyID: 100,
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember}, PreAuthKey: &v1.PreAuthKey{Id: 100}},
			}},
			setTagsErr: errors.New("boom"),
			wantErr:    ErrHeadscaleRequestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeService{
				listNodesResp: tt.listNodesResp,
				listNodesErr:  tt.listNodesErr,
				setTagsErr:    tt.setTagsErr,
			}

			nodeID, err := GrantStorageAccess(context.Background(), fake, tt.preAuthKeyID)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GrantStorageAccess() error = %v, want %v", err, tt.wantErr)
				}
				if nodeID != 0 {
					t.Fatalf("GrantStorageAccess() nodeID = %d on failure, want 0", nodeID)
				}
				return
			}
			if err != nil {
				t.Fatalf("GrantStorageAccess() unexpected error = %v", err)
			}
			if nodeID != tt.wantNodeID {
				t.Fatalf("GrantStorageAccess() nodeID = %d, want %d", nodeID, tt.wantNodeID)
			}
			if fake.gotSetTags == nil {
				t.Fatal("SetTags was not called")
			}
			if fake.gotSetTags.GetNodeId() != tt.wantSetTagsNodeID {
				t.Fatalf("SetTags NodeId = %d, want %d", fake.gotSetTags.GetNodeId(), tt.wantSetTagsNodeID)
			}
			gotTags := fake.gotSetTags.GetTags()
			if len(gotTags) != len(tt.wantTags) {
				t.Fatalf("SetTags Tags = %v, want %v", gotTags, tt.wantTags)
			}
			for i, tag := range tt.wantTags {
				if gotTags[i] != tag {
					t.Fatalf("SetTags Tags = %v, want %v", gotTags, tt.wantTags)
				}
			}
		})
	}
}

// Requirement: NM-F-09
func TestGrantDuration_Is12Hours(t *testing.T) {
	if GrantDuration != 12*time.Hour {
		t.Fatalf("GrantDuration = %v, want 12h (NM-F-09's literal requirement)", GrantDuration)
	}
}

// Requirement: NM-F-10
func TestRemoveNodeTag(t *testing.T) {
	tests := []struct {
		name        string
		getNodeResp *v1.GetNodeResponse
		getNodeErr  error
		setTagsErr  error
		tag         string
		wantErr     error
		wantTags    []string
	}{
		{
			name:        "removes the tag, keeping the rest",
			getNodeResp: &v1.GetNodeResponse{Node: &v1.Node{Id: 42, Tags: []string{TagMeshMember, TagStorageAccess}}},
			tag:         TagStorageAccess,
			wantTags:    []string{TagMeshMember},
		},
		{
			name:        "removing the only tag fails closed, SetTags is never called",
			getNodeResp: &v1.GetNodeResponse{Node: &v1.Node{Id: 42, Tags: []string{TagStorageAccess}}},
			tag:         TagStorageAccess,
			wantErr:     ErrCannotRemoveLastTag,
		},
		{
			name:       "GetNode failure is wrapped in ErrHeadscaleRequestFailed",
			getNodeErr: errors.New("boom"),
			tag:        TagStorageAccess,
			wantErr:    ErrHeadscaleRequestFailed,
		},
		{
			name:        "nil node in response is a fail-secure ErrMeshUserNotFound",
			getNodeResp: &v1.GetNodeResponse{Node: nil},
			tag:         TagStorageAccess,
			wantErr:     ErrMeshUserNotFound,
		},
		{
			name:        "SetTags failure is wrapped in ErrHeadscaleRequestFailed",
			getNodeResp: &v1.GetNodeResponse{Node: &v1.Node{Id: 42, Tags: []string{TagMeshMember, TagStorageAccess}}},
			tag:         TagStorageAccess,
			setTagsErr:  errors.New("boom"),
			wantErr:     ErrHeadscaleRequestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeService{
				getNodeResp: tt.getNodeResp,
				getNodeErr:  tt.getNodeErr,
				setTagsErr:  tt.setTagsErr,
			}

			err := RemoveNodeTag(context.Background(), fake, 42, tt.tag)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("RemoveNodeTag() error = %v, want %v", err, tt.wantErr)
				}
				if errors.Is(tt.wantErr, ErrCannotRemoveLastTag) && fake.gotSetTags != nil {
					t.Fatal("SetTags was called despite the last-tag guard")
				}
				return
			}
			if err != nil {
				t.Fatalf("RemoveNodeTag() unexpected error = %v", err)
			}
			gotTags := fake.gotSetTags.GetTags()
			if len(gotTags) != len(tt.wantTags) {
				t.Fatalf("SetTags Tags = %v, want %v", gotTags, tt.wantTags)
			}
			for i, tag := range tt.wantTags {
				if gotTags[i] != tag {
					t.Fatalf("SetTags Tags = %v, want %v", gotTags, tt.wantTags)
				}
			}
		})
	}
}

// Requirement: NM-F-10
func TestRevokeStorageAccess_RemovesOnlyTheStorageTag(t *testing.T) {
	fake := &fakeService{
		getNodeResp: &v1.GetNodeResponse{Node: &v1.Node{Id: 7, Tags: []string{TagMeshMember, TagStorageAccess}}},
	}

	if err := RevokeStorageAccess(context.Background(), fake, 7); err != nil {
		t.Fatalf("RevokeStorageAccess() unexpected error = %v", err)
	}
	if fake.gotGetNode.GetNodeId() != 7 {
		t.Fatalf("GetNode NodeId = %d, want 7", fake.gotGetNode.GetNodeId())
	}
	gotTags := fake.gotSetTags.GetTags()
	if len(gotTags) != 1 || gotTags[0] != TagMeshMember {
		t.Fatalf("SetTags Tags = %v, want [%s]", gotTags, TagMeshMember)
	}
}

// Requirement: NM-F-09
func TestUnionTag(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		tag      string
		want     []string
	}{
		{name: "appends a new tag", existing: []string{TagMeshMember}, tag: TagStorageAccess, want: []string{TagMeshMember, TagStorageAccess}},
		{name: "no-op if already present", existing: []string{TagMeshMember, TagStorageAccess}, tag: TagStorageAccess, want: []string{TagMeshMember, TagStorageAccess}},
		{name: "empty existing set", existing: nil, tag: TagStorageAccess, want: []string{TagStorageAccess}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unionTag(tt.existing, tt.tag)
			if len(got) != len(tt.want) {
				t.Fatalf("unionTag() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("unionTag() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// Requirement: NM-F-10
func TestRemoveTag(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		tag      string
		want     []string
	}{
		{name: "removes the only matching tag", existing: []string{TagMeshMember, TagStorageAccess}, tag: TagStorageAccess, want: []string{TagMeshMember}},
		{name: "no-op if not present", existing: []string{TagMeshMember}, tag: TagStorageAccess, want: []string{TagMeshMember}},
		{name: "removing the last tag yields an empty set", existing: []string{TagStorageAccess}, tag: TagStorageAccess, want: []string{}},
		{name: "empty existing set", existing: nil, tag: TagStorageAccess, want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeTag(tt.existing, tt.tag)
			if len(got) != len(tt.want) {
				t.Fatalf("removeTag() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("removeTag() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
