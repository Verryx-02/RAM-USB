package headscale_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	hs "github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// Requirement: NM-F-01, NM-F-02, NM-F-04, NM-F-05, NM-F-06, NM-F-07
//
// Confirms PushPolicy against a real Headscale server end to end, over the
// REST transport (see headscale_integration_test.go's own doc comment for
// why): a real PUT /api/v1/policy call, and a real GET /api/v1/policy
// readback proving Headscale accepted and stored exactly the document
// PolicyDocument built - not merely that this package's own marshaling
// round-trips through encoding/json in-process (that is
// TestPolicyDocument_Content's job, which needs no live server). Gated the
// same way as TestCreateMeshUser_AndGrantStorageAccess_RealHeadscale:
// skipped unless NM_TEST_HEADSCALE_ADDR is set.
//
// What this test does NOT cover, and could not practically cover without a
// full multi-node mesh: actually attempting a connection between two
// tagged nodes and confirming it is allowed/blocked by this policy. That
// would need real Tailscale/Headscale clients on both ends of every one of
// NM-F-01/02/04/05/06/07's rules - out of reach for this task per its own
// stated scope boundary; a real policy round trip plus the exact-content
// unit test are this task's practical verification ceiling.
func TestPushPolicy_RealHeadscale(t *testing.T) {
	addr := os.Getenv(headscaleTestAddrEnvVar)
	if addr == "" {
		t.Skipf("%s not set, skipping real-Headscale integration test", headscaleTestAddrEnvVar)
	}

	container := os.Getenv(headscaleTestContainerEnvVar)
	if container == "" {
		container = defaultHeadscaleTestContainer
	}

	apiKey := mintAPIKey(t, container)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // dev-only self-signed reverse-proxy cert, see deployments/docker/headscale/README.txt
		},
		Timeout: 15 * time.Second,
	}
	client := hs.NewClient(addr, httpClient, apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := hs.PushPolicy(ctx, client); err != nil {
		t.Fatalf("PushPolicy() error = %v", err)
	}

	got, err := client.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}

	want, err := hs.PolicyDocument()
	if err != nil {
		t.Fatalf("PolicyDocument() error = %v", err)
	}

	// Compare decoded JSON, not raw bytes: Headscale is free to
	// re-serialize (field order, whitespace) when it stores and returns
	// the policy, and this test's job is to confirm the *content*
	// round-trips, not byte-identical formatting.
	var gotDoc, wantDoc map[string]any
	if err := json.Unmarshal([]byte(got), &gotDoc); err != nil {
		t.Fatalf("json.Unmarshal(GetPolicy() result) error = %v", err)
	}
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatalf("json.Unmarshal(PolicyDocument()) error = %v", err)
	}

	gotJSON, _ := json.Marshal(gotDoc)
	wantJSON, _ := json.Marshal(wantDoc)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("GetPolicy() returned a document that does not match what PushPolicy sent:\ngot:  %s\nwant: %s", gotJSON, wantJSON)
	}
}
