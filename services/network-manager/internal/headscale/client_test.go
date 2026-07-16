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

	listUsersResp *v1.ListUsersResponse
	listUsersErr  error

	listNodesResp *v1.ListNodesResponse
	listNodesErr  error

	setTagsErr error
	gotSetTags *v1.SetTagsRequest
}

func (f *fakeService) CreateUser(_ context.Context, in *v1.CreateUserRequest, _ ...grpc.CallOption) (*v1.CreateUserResponse, error) {
	f.gotCreateUser = in
	if f.createUserErr != nil {
		return nil, f.createUserErr
	}
	return &v1.CreateUserResponse{User: &v1.User{Name: in.GetName(), Email: in.GetEmail()}}, nil
}

func (f *fakeService) ListUsers(_ context.Context, _ *v1.ListUsersRequest, _ ...grpc.CallOption) (*v1.ListUsersResponse, error) {
	if f.listUsersErr != nil {
		return nil, f.listUsersErr
	}
	return f.listUsersResp, nil
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

// Requirement: NM-F-08
func TestCreateMeshUser(t *testing.T) {
	tests := []struct {
		name                string
		createUserErr       error
		createPreAuthKeyErr error
		preAuthKeyResp      *v1.CreatePreAuthKeyResponse
		wantKey             string
		wantErr             error
	}{
		{
			name:           "success returns the generated pre-auth key",
			preAuthKeyResp: &v1.CreatePreAuthKeyResponse{PreAuthKey: &v1.PreAuthKey{Key: "authkey-abc123"}},
			wantKey:        "authkey-abc123",
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

			key, err := CreateMeshUser(context.Background(), fake, "User@Example.com")

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
			// native Email field must carry the real address so
			// NM-F-09 can look the user up by it later.
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
		name          string
		listUsersResp *v1.ListUsersResponse
		listUsersErr  error
		listNodesResp *v1.ListNodesResponse
		listNodesErr  error
		setTagsErr    error
		wantErr       error
		wantTags      []string
	}{
		{
			name: "success adds TagStorageAccess alongside the existing TagMeshMember",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
			}},
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember}},
			}},
			wantTags: []string{TagMeshMember, TagStorageAccess},
		},
		{
			name: "already-granted node is not given a duplicate tag",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
			}},
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember, TagStorageAccess}},
			}},
			wantTags: []string{TagMeshMember, TagStorageAccess},
		},
		{
			name:         "ListUsers failure is wrapped in ErrHeadscaleRequestFailed",
			listUsersErr: errors.New("boom"),
			wantErr:      ErrHeadscaleRequestFailed,
		},
		{
			name:          "no headscale user for this email is a fail-secure ErrMeshUserNotFound",
			listUsersResp: &v1.ListUsersResponse{Users: nil},
			wantErr:       ErrMeshUserNotFound,
		},
		{
			name: "more than one headscale user for this email is a fail-secure ErrMeshUserNotFound",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
				{Name: "u456", Email: "user@example.com"},
			}},
			wantErr: ErrMeshUserNotFound,
		},
		{
			name: "no mesh node for this user is a fail-secure ErrMeshUserNotFound",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
			}},
			listNodesResp: &v1.ListNodesResponse{Nodes: nil},
			wantErr:       ErrMeshUserNotFound,
		},
		{
			name: "ListNodes failure is wrapped in ErrHeadscaleRequestFailed",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
			}},
			listNodesErr: errors.New("boom"),
			wantErr:      ErrHeadscaleRequestFailed,
		},
		{
			name: "SetTags failure is wrapped in ErrHeadscaleRequestFailed",
			listUsersResp: &v1.ListUsersResponse{Users: []*v1.User{
				{Name: "u123", Email: "user@example.com"},
			}},
			listNodesResp: &v1.ListNodesResponse{Nodes: []*v1.Node{
				{Id: 42, Tags: []string{TagMeshMember}},
			}},
			setTagsErr: errors.New("boom"),
			wantErr:    ErrHeadscaleRequestFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeService{
				listUsersResp: tt.listUsersResp,
				listUsersErr:  tt.listUsersErr,
				listNodesResp: tt.listNodesResp,
				listNodesErr:  tt.listNodesErr,
				setTagsErr:    tt.setTagsErr,
			}

			err := GrantStorageAccess(context.Background(), fake, "user@example.com")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("GrantStorageAccess() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GrantStorageAccess() unexpected error = %v", err)
			}
			if fake.gotSetTags == nil {
				t.Fatal("SetTags was not called")
			}
			if fake.gotSetTags.GetNodeId() != 42 {
				t.Fatalf("SetTags NodeId = %d, want 42", fake.gotSetTags.GetNodeId())
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
