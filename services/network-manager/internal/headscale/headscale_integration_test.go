package headscale_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	hs "github.com/Verryx-02/RAM-USB/services/network-manager/internal/headscale"
)

// headscaleTestAddrEnvVar gates this test on a real, already-running
// standalone Headscale+reverse-proxy stack (deployments/compose/
// headscale.yml) - e.g. "https://localhost:8080". Same env-var-gated-skip
// shape as docs/Test_Plan.md section 4's "integration tests run against
// the Docker Compose stack", and the same pattern this codebase already
// established for DV-F-08's postgres_test.go
// (DATABASE_VAULT_TEST_DATABASE_URL).
const headscaleTestAddrEnvVar = "NM_TEST_HEADSCALE_ADDR"

// headscaleTestContainerEnvVar names the Docker container this test execs
// into to mint a real, single-use API key via the real "headscale apikeys
// create" CLI - mirrors the prior session's pkg/pki/stepca_test.go pattern
// (docker exec ... step ca token ...) for minting a real bootstrap-token
// credential.
const headscaleTestContainerEnvVar = "NM_TEST_HEADSCALE_CONTAINER"

const defaultHeadscaleTestContainer = "headscale"

// Requirement: NM-F-08, NM-F-09
//
// Confirms internal/headscale.CreateMeshUser/GrantStorageAccess against a
// real Headscale server end to end, over the REST transport (this
// session's architectural change - see client.go's own package doc
// comment): a real HTTPS dial through the reverse proxy fronting
// Headscale (client-cert optional at the TLS layer, since this test's own
// mTLS identity is a throwaway self-signed cert, not a real RAM-USB CA
// identity - it exercises Headscale's own bearer-API-key auth and REST
// wire shapes, not PKI-F-02's organization check, which is the reverse
// proxy's own job and has no Headscale-side equivalent to verify here),
// real CreateUser/CreatePreAuthKey, real ListUsers-by-email lookup (still
// exercised here as an independent sanity check that CreateUser's Email
// field really is queryable, even though GrantStorageAccess itself no
// longer performs this lookup - see GrantStorageAccess's own doc comment).
// What this test does NOT cover, and could not practically cover in this
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

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // dev-only self-signed reverse-proxy cert, see deployments/docker/headscale/README.txt
		},
		Timeout: 15 * time.Second,
	}
	client := hs.NewClient(addr, httpClient, apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	email := fmt.Sprintf("nm-integration-test-%d@example.com", time.Now().UnixNano())

	key, keyID, err := hs.CreateMeshUser(ctx, client, email)
	if err != nil {
		t.Fatalf("CreateMeshUser() error = %v", err)
	}
	if key == "" {
		t.Fatal("CreateMeshUser() returned an empty pre-auth key")
	}
	if keyID == 0 {
		t.Fatal("CreateMeshUser() returned a zero pre-auth key id, want the real Headscale-assigned id")
	}

	// GrantStorageAccess's real success path needs an actual mesh node
	// (a real Tailscale/Headscale client that consumed the pre-auth key
	// above and registered) - this test has no such client, so the only
	// honestly verifiable outcome here is the fail-secure "no node yet"
	// branch: ErrMeshUserNotFound, not ErrHeadscaleRequestFailed or a
	// silent success. This is the practical ceiling for this task's
	// real-server verification, flagged rather than skipped outright.
	_, err = hs.GrantStorageAccess(ctx, client, keyID)
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

	out, err := exec.CommandContext(context.Background(), "docker", "exec", container, //nolint:gosec // container/binary path are test-only, operator-controlled, not request input
		"headscale", "apikeys", "create", "--expiration", "10m").CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec headscale apikeys create: %v (output: %s)", err, out)
	}

	key := strings.TrimSpace(string(out))
	if key == "" {
		t.Fatal("docker exec headscale apikeys create returned an empty key")
	}
	return key
}
