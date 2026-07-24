package mesh_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Verryx-02/RAM-USB/pkg/mesh"
)

// Same env-var-gated-skip shape as
// services/network-manager/internal/headscale/headscale_integration_test.go
// (NM_TEST_HEADSCALE_ADDR/NM_TEST_HEADSCALE_CONTAINER): this test requires
// a real, already-running standalone headscale container
// (deployments/compose/headscale.yml) reachable at its control URL, plus
// "docker exec" access to mint real users/pre-auth keys via the real
// "headscale" CLI - not a fake/stub. Verified live against that stack.
//
// The pre-auth keys are minted WITH ACL tags (--tags), exactly like the
// real services' keys in deployments/compose/{security-switch,
// database-vault}.yml. This is load-bearing, confirmed live: the running
// Headscale holds Network-Manager's database-mode ACL policy (NM-F-02,
// services/network-manager/internal/headscale/policy.go), whose accept
// rules are all tag-based - a node joined from an untagged key matches no
// rule, so the receiving node's packet filter silently DROPS its inbound
// TCP SYN. The failure shape is treacherous: the join succeeds, the peer
// is still visible in mesh status (netmap visibility is not proof the
// filter allows traffic), and Dial then hangs until its context expires
// without ever returning an error. See pkg/mesh/mesh.go's "ACL policy"
// doc-comment section.
const meshTestControlURLEnvVar = "MESH_TEST_HEADSCALE_CONTROL_URL"

// meshTestContainerEnvVar names the Docker container this test execs into
// to mint real Headscale users/pre-auth keys via the real "headscale"
// CLI - mirrors headscale_integration_test.go's mintAPIKey pattern.
const meshTestContainerEnvVar = "MESH_TEST_HEADSCALE_CONTAINER"

const defaultMeshTestContainer = "headscale"

// Requirement: SS-F-01, DV-F-01
//
// Demonstrates, against a real Headscale server, the central property
// this task exists to establish: a call between two mesh nodes (standing
// in for Security-Switch calling Database-Vault, SS-F-04) succeeds only
// through Server.Dial/Server.Listen, and a listener never becomes
// reachable by any other means - a plain net.Dial to the same node's
// Tailscale IP, issued from this test process (which is not itself a
// tailnet member), fails rather than succeeding by some other route.
// This is what "access to the private mesh network" (SS-F-01/DV-F-01)
// means in practice, completing the acceptance clause that had no real
// mesh node to apply to before this package existed.
func TestServer_DialReachesListener_OnlyThroughMesh_RealHeadscale(t *testing.T) {
	controlURL := os.Getenv(meshTestControlURLEnvVar)
	if controlURL == "" {
		t.Skipf("%s not set, skipping real-Headscale integration test", meshTestControlURLEnvVar)
	}

	container := os.Getenv(meshTestContainerEnvVar)
	if container == "" {
		container = defaultMeshTestContainer
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Tags mirror the SS-F-04 direction this pair stands in for: the ACL
	// policy's accept rule "src tag:security-switch -> dst
	// tag:database-vault:*" is what lets the client node reach the server
	// node at all (see this file's header comment).
	stamp := time.Now().UnixNano()
	serverKey := mintPreAuthKey(t, container, fmt.Sprintf("mesh-test-server-%d", stamp), "tag:database-vault")
	clientKey := mintPreAuthKey(t, container, fmt.Sprintf("mesh-test-client-%d", stamp), "tag:security-switch")

	serverNode, err := mesh.Up(ctx, mesh.Config{
		Dir:        t.TempDir(),
		Hostname:   fmt.Sprintf("mesh-test-server-%d", stamp),
		ControlURL: controlURL,
		AuthKey:    serverKey,
	})
	if err != nil {
		t.Fatalf("mesh.Up() server node error = %v", err)
	}
	defer func() { _ = serverNode.Close() }()

	clientNode, err := mesh.Up(ctx, mesh.Config{
		Dir:        t.TempDir(),
		Hostname:   fmt.Sprintf("mesh-test-client-%d", stamp),
		ControlURL: controlURL,
		AuthKey:    clientKey,
	})
	if err != nil {
		t.Fatalf("mesh.Up() client node error = %v", err)
	}
	defer func() { _ = clientNode.Close() }()

	ln, err := serverNode.Listen("tcp", ":8945")
	if err != nil {
		t.Fatalf("serverNode.Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()

	const wantBody = "reached only through the mesh"
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, wantBody)
		}))
	}()

	// Positive case: a call issued through clientNode.Dial (the same
	// mechanism buildDatabaseVaultClient's Transport.DialContext uses in
	// both services' main.go) succeeds.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: clientNode.Dial,
		},
		// 30s, not 15s: two nodes that join Headscale within moments of
		// each other can still be mid-WireGuard-handshake by the time
		// this Get fires - Server.Dial's retry-with-backoff loop (see
		// pkg/mesh/mesh.go's "Data-plane readiness is NOT a resolution
		// gate" doc comment) needs headroom beyond simple mesh-status
		// hostname visibility, because each retry is itself what triggers
		// the lazy handshake. This Timeout is also the only bound
		// governing that loop here, since http.Client.Get uses
		// context.Background() internally, not this test's own outer ctx.
		Timeout: 30 * time.Second,
	}
	resp, err := httpClient.Get("http://mesh-test-server-" + strconv.FormatInt(stamp, 10) + ":8945")
	if err != nil {
		t.Fatalf("httpClient.Get() over the mesh error = %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body error = %v", err)
	}
	if string(body) != wantBody {
		t.Fatalf("response body = %q, want %q", body, wantBody)
	}

	// Negative case: the central property under test. serverNode's
	// listener exists only inside tsnet's own userspace netstack -
	// nothing is ever bound on this host/container's real network
	// interfaces. A plain net.Dial, issued from this test process (not a
	// tailnet member of its own), to the server node's real Tailscale IP
	// must fail, proving the listener has no other reachable path.
	ip4, _ := serverNode.TailscaleIPs()
	if !ip4.IsValid() {
		t.Fatal("serverNode.TailscaleIPs() returned no valid IPv4 address")
	}
	directConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip4.String(), "8945"), 5*time.Second)
	if err == nil {
		_ = directConn.Close()
		t.Fatalf("net.DialTimeout() to %s:8945 succeeded from outside the mesh, want a failure - the listener must be reachable only via Server.Dial", ip4)
	}
}

// Requirement: SS-F-01, DV-F-01
//
// Confirms clean shutdown: Close after no outstanding Listen/Dial leaves
// no goroutine/resource hang - Close's own internal 5s timeout must not
// be needed here (mirrors this codebase's existing *_RealCA_* style
// shutdown checks, e.g. TestBuildServerTLSConfig_RealCA_EnforcesOrganization's
// sibling shutdown assertions elsewhere in this project).
func TestServer_Close_ShutsDownCleanly_RealHeadscale(t *testing.T) {
	controlURL := os.Getenv(meshTestControlURLEnvVar)
	if controlURL == "" {
		t.Skipf("%s not set, skipping real-Headscale integration test", meshTestControlURLEnvVar)
	}

	container := os.Getenv(meshTestContainerEnvVar)
	if container == "" {
		container = defaultMeshTestContainer
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stamp := time.Now().UnixNano()
	key := mintPreAuthKey(t, container, fmt.Sprintf("mesh-test-shutdown-%d", stamp), "tag:security-switch")

	node, err := mesh.Up(ctx, mesh.Config{
		Dir:        t.TempDir(),
		Hostname:   fmt.Sprintf("mesh-test-shutdown-%d", stamp),
		ControlURL: controlURL,
		AuthKey:    key,
	})
	if err != nil {
		t.Fatalf("mesh.Up() error = %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- node.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close() did not return within 10s - possible goroutine/resource hang")
	}

	// Idempotent per tsnet's own doc comment.
	if err := node.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil (idempotent)", err)
	}
}

// mintPreAuthKey shells out to the real "headscale" CLI inside the
// running container: creates a fresh Headscale user (if not already
// present) and mints a single-use pre-auth key for it, tagged with tag -
// the same operator-driven, real-artifact-minting pattern
// headscale_integration_test.go's mintAPIKey already established for API
// keys, and the same --tags requirement the real services' compose files
// document (see this file's header comment for why an untagged key
// produces a node whose traffic the ACL policy silently drops).
func mintPreAuthKey(t *testing.T, container, username, tag string) string {
	t.Helper()

	// "headscale users create" is idempotent-by-intent for this test's
	// purposes: a duplicate-name error is tolerated (each username here
	// is already unique per stamp), any other error is fatal.
	if out, err := exec.CommandContext(context.Background(), "docker", "exec", container, //nolint:gosec // container/binary path are test-only, operator-controlled, not request input
		"/ko-app/headscale", "users", "create", username).CombinedOutput(); err != nil {
		t.Fatalf("docker exec headscale users create %s: %v (output: %s)", username, err, out)
	}

	listOut, err := exec.CommandContext(context.Background(), "docker", "exec", container, //nolint:gosec // see above
		"/ko-app/headscale", "users", "list", "--name", username, "-o", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec headscale users list %s: %v (output: %s)", username, err, listOut)
	}

	var users []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(listOut, &users); err != nil {
		t.Fatalf("parse headscale users list output: %v (output: %s)", err, listOut)
	}
	if len(users) != 1 {
		t.Fatalf("headscale users list --name %s returned %d users, want 1", username, len(users))
	}

	keyOut, err := exec.CommandContext(context.Background(), "docker", "exec", container, //nolint:gosec // see above
		"/ko-app/headscale", "preauthkeys", "create", "--user", strconv.FormatInt(users[0].ID, 10), "--expiration", "15m", "--tags", tag).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec headscale preauthkeys create: %v (output: %s)", err, keyOut)
	}

	key := strings.TrimSpace(string(keyOut))
	if key == "" {
		t.Fatal("docker exec headscale preauthkeys create returned an empty key")
	}
	return key
}
