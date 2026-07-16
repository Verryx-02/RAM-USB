package headscale_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"

	hs "github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// headscaleTestAddrEnvVar gates this test on a real, already-running
// network-manager-headscale container (deployments/docker-compose.dev.yml).
// Same env-var-gated-skip shape as docs/Test_Plan.md §4's "integration
// tests run against the Docker Compose stack", and the same pattern this
// codebase already established for DV-F-08's postgres_test.go
// (DATABASE_VAULT_TEST_DATABASE_URL).
const headscaleTestAddrEnvVar = "NM_TEST_HEADSCALE_ADDR"

// headscaleTestContainerEnvVar names the Docker container this test execs
// into to mint a real, single-use API key via the real "headscale
// apikeys create" CLI - mirrors the prior session's pkg/pki/stepca_test.go
// pattern (docker exec ... step ca token ...) for minting a real
// bootstrap-token credential, per this session's own memory notes.
const headscaleTestContainerEnvVar = "NM_TEST_HEADSCALE_CONTAINER"

const defaultHeadscaleTestContainer = "deployments-network-manager-headscale-1"

// Requirement: NM-F-08, NM-F-09
//
// Confirms internal/headscale.CreateMeshUser/GrantStorageAccess against a
// real Headscale server end to end: real gRPC dial (TLS, bearer API key),
// real CreateUser/CreatePreAuthKey, real ListUsers-by-email lookup. What
// this test does NOT cover, and could not practically cover in this
// session: GrantStorageAccess's success path requires an already-
// registered mesh *node* (a real Tailscale/Headscale client consuming the
// pre-auth key and joining), which this test has no client to do - see
// the test's own final assertion for exactly how far verification goes.
func TestCreateMeshUser_AndGrantStorageAccess_RealHeadscale(t *testing.T) {
	addr := os.Getenv(headscaleTestAddrEnvVar)
	if addr == "" {
		t.Skipf("%s not set, skipping real-Headscale integration test", headscaleTestAddrEnvVar)
	}

	container := os.Getenv(headscaleTestContainerEnvVar)
	if container == "" {
		container = defaultHeadscaleTestContainer
	}

	apiKey := mintAPIKey(t, container)

	conn, err := hs.Dial(addr, apiKey, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // dev-only self-signed cert, see third-party/network-manager/headscale/dev-tls/README.txt
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := v1.NewHeadscaleServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	email := fmt.Sprintf("nm-integration-test-%d@example.com", time.Now().UnixNano())

	key, err := hs.CreateMeshUser(ctx, client, email)
	if err != nil {
		t.Fatalf("CreateMeshUser() error = %v", err)
	}
	if key == "" {
		t.Fatal("CreateMeshUser() returned an empty pre-auth key")
	}

	// Confirms NM-F-08's real user creation and the Email-based lookup
	// NM-F-09 depends on (internal/headscale's own doc comment) -
	// ListUsers(Email:...) must find exactly the user CreateMeshUser just
	// created.
	users, err := client.ListUsers(ctx, &v1.ListUsersRequest{Email: email})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users.GetUsers()) != 1 {
		t.Fatalf("ListUsers(Email=%q) returned %d users, want 1", email, len(users.GetUsers()))
	}

	// GrantStorageAccess's real success path needs an actual mesh node
	// (a real Tailscale/Headscale client that consumed the pre-auth key
	// above and registered) - this test has no such client, so the only
	// honestly verifiable outcome here is the fail-secure "no node yet"
	// branch: ErrMeshUserNotFound, not ErrHeadscaleRequestFailed or a
	// silent success. This is the practical ceiling for this task's
	// real-server verification, flagged rather than skipped outright.
	err = hs.GrantStorageAccess(ctx, client, email)
	if !errors.Is(err, hs.ErrMeshUserNotFound) {
		t.Fatalf("GrantStorageAccess() error = %v, want ErrMeshUserNotFound (no real mesh node has joined in this test)", err)
	}
}

// mintAPIKey shells out to the real "headscale apikeys create" CLI inside
// the running container, the same real-artifact-minting approach as the
// prior session's pkg/pki/stepca_test.go ("docker exec ... step ca token
// ..."), not a hand-typed fixture value.
func mintAPIKey(t *testing.T, container string) string {
	t.Helper()

	out, err := exec.Command("docker", "exec", container, //nolint:gosec // container/binary path are test-only, operator-controlled, not request input
		"/ko-app/headscale", "apikeys", "create", "--expiration", "10m").CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec headscale apikeys create: %v (output: %s)", err, out)
	}

	key := strings.TrimSpace(string(out))
	if key == "" {
		t.Fatal("docker exec headscale apikeys create returned an empty key")
	}
	return key
}
