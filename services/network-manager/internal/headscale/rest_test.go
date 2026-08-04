package headscale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestServer starts an httptest.Server invoking handler for every
// request, and returns a Client pointed at it - CONTRIBUTING.md
// section 7.5's hand-written-fake convention applied at the HTTP boundary
// itself (a real net/http round trip, not a mocked RoundTripper), the same
// verification depth pkg/metrics' own real-paho-broker tests use.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, srv.Client(), "test-api-key"), srv
}

// Requirement: NM-F-08
func TestClient_CreateUser(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	var gotBody createUserRequest

	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(createUserResponse{User: restUser{ID: "42"}})
	})

	userID, err := client.CreateUser(context.Background(), "uabc123", "user@example.com")
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if userID != 42 {
		t.Fatalf("CreateUser() userID = %d, want 42", userID)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/user" {
		t.Fatalf("path = %q, want /api/v1/user", gotPath)
	}
	if gotAuth != "Bearer test-api-key" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer test-api-key")
	}
	if gotBody.Name != "uabc123" || gotBody.Email != "user@example.com" {
		t.Fatalf("request body = %+v, want Name=uabc123 Email=user@example.com", gotBody)
	}
}

// Requirement: NM-F-08
func TestClient_CreatePreAuthKey(t *testing.T) {
	var gotPath string
	var gotBody createPreAuthKeyRequest

	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(createPreAuthKeyResponse{
			PreAuthKey: restPreAuthKey{ID: "7", Key: "authkey-xyz"},
		})
	})

	expiration := time.Now().Add(15 * time.Minute)
	key, keyID, err := client.CreatePreAuthKey(context.Background(), 42, expiration, []string{"tag:mesh-member"})
	if err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
	if key != "authkey-xyz" || keyID != 7 {
		t.Fatalf("CreatePreAuthKey() = (%q, %d), want (authkey-xyz, 7)", key, keyID)
	}
	if gotPath != "/api/v1/preauthkey" {
		t.Fatalf("path = %q, want /api/v1/preauthkey", gotPath)
	}
	if gotBody.User != "42" {
		t.Fatalf("request body User = %q, want %q (uint64-as-string)", gotBody.User, "42")
	}
	if gotBody.Reusable || gotBody.Ephemeral {
		t.Fatalf("request body Reusable/Ephemeral = %v/%v, want false/false", gotBody.Reusable, gotBody.Ephemeral)
	}
	if gotBody.Expiration.IsZero() {
		t.Fatal("request body Expiration = zero, want the explicit deadline passed in")
	}
	if len(gotBody.ACLTags) != 1 || gotBody.ACLTags[0] != "tag:mesh-member" {
		t.Fatalf("request body ACLTags = %v, want [tag:mesh-member]", gotBody.ACLTags)
	}
}

// Requirement: NM-F-09
func TestClient_ListNodes(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/node" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(listNodesResponse{Nodes: []restNode{
			{ID: "1", Tags: []string{"tag:mesh-member"}, PreAuthKey: &restPreAuthKey{ID: "100"}},
			{ID: "2", Tags: []string{"tag:mesh-member"}}, // no pre-auth key at all
		}})
	})

	nodes, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes() error = %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("ListNodes() returned %d nodes, want 2", len(nodes))
	}
	if nodes[0].ID != 1 || nodes[0].PreAuthKeyID != 100 {
		t.Fatalf("nodes[0] = %+v, want ID=1 PreAuthKeyID=100", nodes[0])
	}
	if nodes[1].ID != 2 || nodes[1].PreAuthKeyID != 0 {
		t.Fatalf("nodes[1] = %+v, want ID=2 PreAuthKeyID=0 (no pre-auth key)", nodes[1])
	}
}

// Requirement: NM-F-10
func TestClient_GetNode(t *testing.T) {
	var gotPath string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(getNodeResponse{Node: restNode{ID: "5", Tags: []string{"tag:mesh-member"}}})
	})

	node, err := client.GetNode(context.Background(), 5)
	if err != nil {
		t.Fatalf("GetNode() error = %v", err)
	}
	if node.ID != 5 {
		t.Fatalf("GetNode() ID = %d, want 5", node.ID)
	}
	if gotPath != "/api/v1/node/5" {
		t.Fatalf("path = %q, want /api/v1/node/5", gotPath)
	}
}

// Requirement: NM-F-09
func TestClient_SetTags(t *testing.T) {
	var gotPath string
	var gotBody setTagsRequestBody
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	if err := client.SetTags(context.Background(), 5, []string{"tag:mesh-member", "tag:storage-access"}); err != nil {
		t.Fatalf("SetTags() error = %v", err)
	}
	if gotPath != "/api/v1/node/5/tags" {
		t.Fatalf("path = %q, want /api/v1/node/5/tags", gotPath)
	}
	if len(gotBody.Tags) != 2 {
		t.Fatalf("request body Tags = %v, want 2 entries", gotBody.Tags)
	}
}

// Requirement: NM-F-01, NM-F-02, NM-F-04, NM-F-05, NM-F-06, NM-F-07
func TestClient_SetPolicy_And_GetPolicy(t *testing.T) {
	var stored string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			var body setPolicyRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			stored = body.Policy
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(getPolicyResponse{Policy: stored})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})

	if err := client.SetPolicy(context.Background(), `{"acls":[]}`); err != nil {
		t.Fatalf("SetPolicy() error = %v", err)
	}
	got, err := client.GetPolicy(context.Background())
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got != `{"acls":[]}` {
		t.Fatalf("GetPolicy() = %q, want %q", got, `{"acls":[]}`)
	}
}

// Requirement: RD-04
//
// A non-2xx response is a hard failure, not a silently-empty success -
// every Service/PolicyPusher method funnels through do(), so this proves
// the shared error path once.
func TestClient_NonSuccessStatus_IsAnError(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"denied"}`))
	})

	if _, err := client.CreateUser(context.Background(), "u", "e@example.com"); err == nil {
		t.Fatal("CreateUser() error = nil, want a wrapped error for HTTP 403")
	}
}

// Requirement: RD-04
//
// parseID fails closed on a malformed id string rather than silently
// returning 0 (which client.go's Node.PreAuthKeyID treats as "absent" -
// silently swallowing a malformed-but-non-empty id would risk a false
// "no pre-auth key" read).
func TestParseID(t *testing.T) {
	if _, err := parseID("not-a-number"); err == nil {
		t.Fatal("parseID(\"not-a-number\") error = nil, want non-nil")
	}
	id, err := parseID("")
	if err != nil || id != 0 {
		t.Fatalf("parseID(\"\") = (%d, %v), want (0, nil)", id, err)
	}
	id, err = parseID("18446744073709551615") // math.MaxUint64
	if err != nil || id != 18446744073709551615 {
		t.Fatalf("parseID(MaxUint64) = (%d, %v), want (MaxUint64, nil)", id, err)
	}
}

// Requirement: NM-F-08
//
// formatID/parseID round-trip for every value client.go's callers pass
// through them (0 included, even though a real Headscale ID is never 0 -
// this just proves the encoding itself is lossless).
func TestFormatID_ParseID_RoundTrip(t *testing.T) {
	for _, id := range []uint64{0, 1, 42, 18446744073709551615} {
		got, err := parseID(formatID(id))
		if err != nil {
			t.Fatalf("parseID(formatID(%d)) error = %v", id, err)
		}
		if got != id {
			t.Fatalf("parseID(formatID(%d)) = %d, want %d", id, got, id)
		}
	}
}

// Requirement: RD-04
//
// A malformed response body (valid HTTP status, undecodable JSON) is an
// error, not a zero-value success.
func TestClient_MalformedResponseBody_IsAnError(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	})

	if _, err := client.CreateUser(context.Background(), "u", "e@example.com"); err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil for an undecodable response body")
	}
}

// Requirement: RD-04
//
// A transport-level failure (server unreachable) surfaces as a non-nil
// error, not a silent zero-value success.
func TestClient_TransportFailure_IsAnError(t *testing.T) {
	client := NewClient("https://127.0.0.1:1", http.DefaultClient, "test-api-key")
	if _, err := client.CreateUser(context.Background(), "u", "e@example.com"); err == nil {
		t.Fatal("CreateUser() error = nil, want non-nil when the server is unreachable")
	}
}
