package headscale

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeService is a hand-written fake of Service (CONTRIBUTING.md
// section 7.5, docs/Test_Plan.md section 2.1: table-driven unit tests use
// hand-written fakes, no real Headscale server).
type fakeService struct {
	createUserErr error
	createUserID  uint64
	gotCreateUser struct {
		name  string
		email string
	}

	createPreAuthKeyErr error
	preAuthKey          string
	preAuthKeyID        uint64
	gotCreatePreAuthKey struct {
		userID     uint64
		expiration time.Time
		aclTags    []string
	}

	listNodesResp []Node
	listNodesErr  error

	setTagsErr error
	gotSetTags struct {
		nodeID uint64
		tags   []string
	}

	getNodeResp Node
	getNodeErr  error
	gotGetNode  uint64
}

func (f *fakeService) CreateUser(_ context.Context, name, email string) (uint64, error) {
	f.gotCreateUser.name = name
	f.gotCreateUser.email = email
	if f.createUserErr != nil {
		return 0, f.createUserErr
	}
	return f.createUserID, nil
}

func (f *fakeService) CreatePreAuthKey(_ context.Context, userID uint64, expiration time.Time, aclTags []string) (string, uint64, error) {
	f.gotCreatePreAuthKey.userID = userID
	f.gotCreatePreAuthKey.expiration = expiration
	f.gotCreatePreAuthKey.aclTags = aclTags
	if f.createPreAuthKeyErr != nil {
		return "", 0, f.createPreAuthKeyErr
	}
	return f.preAuthKey, f.preAuthKeyID, nil
}

func (f *fakeService) ListNodes(_ context.Context) ([]Node, error) {
	if f.listNodesErr != nil {
		return nil, f.listNodesErr
	}
	return f.listNodesResp, nil
}

func (f *fakeService) SetTags(_ context.Context, nodeID uint64, tags []string) error {
	f.gotSetTags.nodeID = nodeID
	f.gotSetTags.tags = tags
	if f.setTagsErr != nil {
		return f.setTagsErr
	}
	return nil
}

func (f *fakeService) GetNode(_ context.Context, nodeID uint64) (Node, error) {
	f.gotGetNode = nodeID
	if f.getNodeErr != nil {
		return Node{}, f.getNodeErr
	}
	return f.getNodeResp, nil
}

// Requirement: NM-F-08
func TestCreateMeshUser(t *testing.T) {
	tests := []struct {
		name                string
		createUserErr       error
		createUserID        uint64
		createPreAuthKeyErr error
		preAuthKey          string
		preAuthKeyID        uint64
		wantKey             string
		wantKeyID           uint64
		wantErr             error
	}{
		{
			name:         "success returns the generated pre-auth key and its numeric id",
			createUserID: 7,
			preAuthKey:   "authkey-abc123",
			preAuthKeyID: 42,
			wantKey:      "authkey-abc123",
			wantKeyID:    42,
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
			name:       "empty key in response is treated as a failure",
			preAuthKey: "",
			wantErr:    ErrHeadscaleRequestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeService{
				createUserErr:       tt.createUserErr,
				createUserID:        tt.createUserID,
				createPreAuthKeyErr: tt.createPreAuthKeyErr,
				preAuthKey:          tt.preAuthKey,
				preAuthKeyID:        tt.preAuthKeyID,
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
			if got := fake.gotCreatePreAuthKey.aclTags; len(got) != 1 || got[0] != TagMeshMember {
				t.Fatalf("CreatePreAuthKey aclTags = %v, want [%s]", got, TagMeshMember)
			}
			if fake.gotCreatePreAuthKey.expiration.IsZero() {
				t.Fatal("CreatePreAuthKey expiration = zero, want an explicit deadline (the flagged omitted-expiration bug)")
			}
			if fake.gotCreatePreAuthKey.userID != tt.createUserID {
				t.Fatalf("CreatePreAuthKey userID = %d, want %d", fake.gotCreatePreAuthKey.userID, tt.createUserID)
			}

			// The generated username must be deterministic and
			// case-insensitive w.r.t. the email (mirrors DV-F-03's
			// hashing.HashEmail normalization rationale), and the
			// native Email field must carry the real address (still
			// useful for a human operator inspecting Headscale
			// directly, even though NM-F-09 no longer looks the user
			// up by it - see GrantStorageAccess's own doc comment).
			if fake.gotCreateUser.email != "User@Example.com" {
				t.Fatalf("CreateUser email = %q, want the exact caller-supplied email", fake.gotCreateUser.email)
			}
			if got := meshUsername("User@Example.com"); got != meshUsername("user@example.com") {
				t.Fatalf("meshUsername is not case-insensitive: %q != %q", got, meshUsername("user@example.com"))
			}
			if fake.gotCreateUser.name != meshUsername("User@Example.com") {
				t.Fatalf("CreateUser name = %q, want %q", fake.gotCreateUser.name, meshUsername("User@Example.com"))
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
		listNodesResp     []Node
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
			listNodesResp: []Node{
				{ID: 42, Tags: []string{TagMeshMember}, PreAuthKeyID: 100},
			},
			wantTags:          []string{TagMeshMember, TagStorageAccess},
			wantNodeID:        42,
			wantSetTagsNodeID: 42,
		},
		{
			name:         "already-granted node is not given a duplicate tag",
			preAuthKeyID: 100,
			listNodesResp: []Node{
				{ID: 42, Tags: []string{TagMeshMember, TagStorageAccess}, PreAuthKeyID: 100},
			},
			wantTags:          []string{TagMeshMember, TagStorageAccess},
			wantNodeID:        42,
			wantSetTagsNodeID: 42,
		},
		{
			// This is the actual proof this session's live-reproduced
			// bug is fixed: several other users' nodes are also on the
			// mesh, each with its own distinct PreAuthKeyID (none of
			// them owned by a "user" a per-user ListUsers/ListNodes
			// lookup could ever have matched anyway, since every node
			// here is tagged, not user-owned). GrantStorageAccess must
			// select the ONE node whose PreAuthKeyID equals the
			// caller-supplied preAuthKeyID - not the first node in the
			// list, not a random one.
			name:         "selects the one node whose pre-auth key id matches, among several other users' nodes",
			preAuthKeyID: 200,
			listNodesResp: []Node{
				{ID: 10, Tags: []string{TagMeshMember}, PreAuthKeyID: 100},
				{ID: 20, Tags: []string{TagMeshMember}, PreAuthKeyID: 200},
				{ID: 30, Tags: []string{TagMeshMember}, PreAuthKeyID: 300},
			},
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
			listNodesResp: []Node{
				{ID: 10, Tags: []string{TagMeshMember}, PreAuthKeyID: 100},
				{ID: 20, Tags: []string{TagMeshMember}, PreAuthKeyID: 200},
			},
			wantErr: ErrMeshUserNotFound,
		},
		{
			name:          "empty node list is a fail-secure ErrMeshUserNotFound",
			preAuthKeyID:  100,
			listNodesResp: nil,
			wantErr:       ErrMeshUserNotFound,
		},
		{
			name:         "a node with no pre-auth key at all never matches",
			preAuthKeyID: 100,
			listNodesResp: []Node{
				{ID: 10, Tags: []string{TagMeshMember}, PreAuthKeyID: 0},
			},
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
			listNodesResp: []Node{
				{ID: 42, Tags: []string{TagMeshMember}, PreAuthKeyID: 100},
			},
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
			if fake.gotSetTags.nodeID != tt.wantSetTagsNodeID {
				t.Fatalf("SetTags nodeID = %d, want %d", fake.gotSetTags.nodeID, tt.wantSetTagsNodeID)
			}
			gotTags := fake.gotSetTags.tags
			if len(gotTags) != len(tt.wantTags) {
				t.Fatalf("SetTags tags = %v, want %v", gotTags, tt.wantTags)
			}
			for i, tag := range tt.wantTags {
				if gotTags[i] != tag {
					t.Fatalf("SetTags tags = %v, want %v", gotTags, tt.wantTags)
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
		getNodeResp Node
		getNodeErr  error
		setTagsErr  error
		tag         string
		wantErr     error
		wantTags    []string
	}{
		{
			name:        "removes the tag, keeping the rest",
			getNodeResp: Node{ID: 42, Tags: []string{TagMeshMember, TagStorageAccess}},
			tag:         TagStorageAccess,
			wantTags:    []string{TagMeshMember},
		},
		{
			name:        "removing the only tag fails closed, SetTags is never called",
			getNodeResp: Node{ID: 42, Tags: []string{TagStorageAccess}},
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
			name:        "SetTags failure is wrapped in ErrHeadscaleRequestFailed",
			getNodeResp: Node{ID: 42, Tags: []string{TagMeshMember, TagStorageAccess}},
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
				if errors.Is(tt.wantErr, ErrCannotRemoveLastTag) && fake.gotSetTags.tags != nil {
					t.Fatal("SetTags was called despite the last-tag guard")
				}
				return
			}
			if err != nil {
				t.Fatalf("RemoveNodeTag() unexpected error = %v", err)
			}
			gotTags := fake.gotSetTags.tags
			if len(gotTags) != len(tt.wantTags) {
				t.Fatalf("SetTags tags = %v, want %v", gotTags, tt.wantTags)
			}
			for i, tag := range tt.wantTags {
				if gotTags[i] != tag {
					t.Fatalf("SetTags tags = %v, want %v", gotTags, tt.wantTags)
				}
			}
		})
	}
}

// Requirement: NM-F-10
func TestRevokeStorageAccess_RemovesOnlyTheStorageTag(t *testing.T) {
	fake := &fakeService{
		getNodeResp: Node{ID: 7, Tags: []string{TagMeshMember, TagStorageAccess}},
	}

	if err := RevokeStorageAccess(context.Background(), fake, 7); err != nil {
		t.Fatalf("RevokeStorageAccess() unexpected error = %v", err)
	}
	if fake.gotGetNode != 7 {
		t.Fatalf("GetNode nodeID = %d, want 7", fake.gotGetNode)
	}
	gotTags := fake.gotSetTags.tags
	if len(gotTags) != 1 || gotTags[0] != TagMeshMember {
		t.Fatalf("SetTags tags = %v, want [%s]", gotTags, TagMeshMember)
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
