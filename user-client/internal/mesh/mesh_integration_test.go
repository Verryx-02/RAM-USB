package mesh_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// cl05HeadscaleContainerEnvVar gates this test on a real, already-running
// standalone Headscale container (deployments/compose/headscale.yml) with
// MagicDNS enabled (third-party/headscale/config/config.yaml's
// dns.magic_dns/base_domain, NM-F-15) - same env-var-gated-skip shape as
// services/network-manager/internal/headscale/headscale_integration_test.go's
// NM_TEST_HEADSCALE_ADDR. Unlike that test, this one talks to Headscale
// entirely through "docker exec ... headscale ..." (the operator CLI, same
// as headscale.sh/e2e-test.sh already do), never Headscale's REST API - no
// reverse-proxy/mTLS admin credential is needed for what this test proves.
const cl05HeadscaleContainerEnvVar = "CL_TEST_HEADSCALE_CONTAINER"

// TestResolveStorageService_RealMagicDNS_RealHeadscale proves CL-F-05
// ("resolve Storage-Service via MagicDNS, without relying on static IP
// addresses") against real infrastructure: a real Headscale server, two
// real tailscale/tailscale containers joining it with real, freshly minted
// pre-auth keys, and a real net.Resolver.LookupHost call (dnsprobe, see
// testdata/dnsprobe/main.go) executed inside a real mesh-joined node's own
// network namespace.
//
// # Why two containers, not the host's own tailscale client
//
// mesh.Join (CL-F-04) shells out to whatever "tailscale" binary is on the
// caller's own PATH - on a real user's machine that means the actual host
// OS joins the mesh. Doing that from an automated test would permanently
// reconfigure the machine running "go test" (a real, persistent Tailscale
// login, exactly like running "tailscale up" by hand) - unacceptable for
// something that must be safe to enable in a disposable CI/dev-VM
// environment described by MANUAL-DISTRIBUTED-RUN.md, let alone a
// developer's primary laptop. Two disposable tailscale/tailscale
// containers (this project's own established stand-in, see
// deployments/compose/tailscale-test.yml's own doc comment: "verifies a
// real mesh join... ephemeral by nature") give the exact same real
// tailscale-CLI-driven join and real MagicDNS resolution without ever
// touching the host's own network configuration - both containers are
// removed (t.Cleanup) when the test ends.
//
// # Why net.Resolver must run inside a container, not this test's own process
//
// Tailscale's own MagicDNS is served by each joined node's local stub
// resolver at 100.100.100.100 (tailscale.com/kb/1054/dns) - reachable only
// from inside that node's own network/mount namespace, and (confirmed live
// this session) NOT wired into a plain Docker container's /etc/resolv.conf
// even with TS_ACCEPT_DNS=true, because Docker's own embedded resolver
// (127.0.0.11) already owns that file and tailscaled correctly declines to
// fight it. dnsprobe is therefore built as a small static Go binary, copied
// into the "client" stand-in container, and run there via "docker exec" -
// the real net.Resolver.LookupHost call this test asserts on executes
// inside a real mesh member's namespace, where 100.100.100.100 genuinely
// answers.
//
// # How this proves the resolved address is dynamic, not hardcoded
//
// Two independent Storage-Service stand-in nodes are registered under two
// different hostnames in the same test run, each with its own freshly
// minted pre-auth key. Each one's resolved address is asserted equal to
// Headscale's OWN live view of that specific node's IP (fetched
// independently via "headscale nodes list"), and the two resolved
// addresses are asserted different from each other - a hardcoded/static
// value in this codebase could satisfy at most one of those two nodes, so
// this pair of assertions would fail if resolution ever fell back to a
// fixed literal instead of genuinely querying MagicDNS.
//
// Requirement: CL-F-05
func TestResolveStorageService_RealMagicDNS_RealHeadscale(t *testing.T) {
	headscaleContainer := os.Getenv(cl05HeadscaleContainerEnvVar)
	if headscaleContainer == "" {
		t.Skipf("%s not set, skipping real-Headscale/real-tailscale CL-F-05 integration test", cl05HeadscaleContainerEnvVar)
	}
	requireBinary(t, "docker")

	devTLSCert := repoRootFile(t, "third-party/headscale/dev-tls/cert.dev-only.pem")
	if _, err := os.Stat(devTLSCert); err != nil {
		t.Skipf("dev-only Headscale reverse-proxy certificate not found at %s (run deployments/scripts/headscale.sh first): %v", devTLSCert, err)
	}

	baseDomain := headscaleBaseDomain(t, headscaleContainer)
	probeBinary := buildDNSProbe(t)

	suffix := time.Now().UnixNano()
	userName := fmt.Sprintf("cl-f-05-test-%d", suffix)
	userID := headscaleUserCreate(t, headscaleContainer, userName)

	// Two independent Storage-Service stand-ins - see the test's own doc
	// comment for why two, not one.
	storageAHost := fmt.Sprintf("cl-f-05-storage-a-%d", suffix)
	storageBHost := fmt.Sprintf("cl-f-05-storage-b-%d", suffix)
	clientHost := fmt.Sprintf("cl-f-05-client-%d", suffix)

	// Tagged with the SAME real ACL tags NM-F-09's grant model uses
	// (tag:storage-access on the client, tag:storage-service on
	// Storage-Service itself) - not just tag:mesh-member. Headscale's own
	// ACL policy restricts NetworkMap/DNS peer visibility to nodes with an
	// overlapping ACL rule (confirmed live this session: two
	// tag:mesh-member-only nodes could not resolve each other at all,
	// "no such host"), so this also faithfully reproduces CL-F-05's real
	// precondition per the SRS: "requires an active ACL grant from UC-02".
	startStandinNode(t, headscaleContainer, devTLSCert, userID, storageAHost, "tag:storage-service")
	startStandinNode(t, headscaleContainer, devTLSCert, userID, storageBHost, "tag:storage-service")
	clientContainer := startStandinNode(t, headscaleContainer, devTLSCert, userID, clientHost, "tag:storage-access")

	headscaleIPA := waitForNodeIPv4(t, headscaleContainer, storageAHost)
	headscaleIPB := waitForNodeIPv4(t, headscaleContainer, storageBHost)

	copyIntoContainer(t, clientContainer, probeBinary, "/dnsprobe")

	resolvedA := runDNSProbeWithRetry(t, clientContainer, storageAHost+"."+baseDomain)
	resolvedB := runDNSProbeWithRetry(t, clientContainer, storageBHost+"."+baseDomain)

	if resolvedA != headscaleIPA {
		t.Errorf("real net.Resolver.LookupHost(%q) = %q, want Headscale's own live node IP %q", storageAHost, resolvedA, headscaleIPA)
	}
	if resolvedB != headscaleIPB {
		t.Errorf("real net.Resolver.LookupHost(%q) = %q, want Headscale's own live node IP %q", storageBHost, resolvedB, headscaleIPB)
	}
	if resolvedA == resolvedB {
		t.Errorf("both stand-in nodes resolved to the same address %q - MagicDNS resolution is not behaving dynamically per-registration", resolvedA)
	}
}

// requireBinary skips the test cleanly when name is not on PATH, rather
// than failing - same fail-clean shape as this codebase's other
// real-infrastructure-gated tests.
func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found on PATH, skipping", name)
	}
}

// repoRootFile resolves path relative to the repository root, found via
// this test file's own location (three levels above
// user-client/internal/mesh/).
func repoRootFile(t *testing.T, path string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(root, path)
}

// headscaleBaseDomain reads dns.base_domain out of Headscale's own live
// config, rather than hardcoding NM-F-15's ramusb-mesh.internal literal
// here too - a config file this test does not own is the one source of
// truth for the domain suffix a resolved hostname needs.
var baseDomainPattern = regexp.MustCompile(`(?m)^\s*base_domain:\s*(\S+)\s*$`)

func headscaleBaseDomain(t *testing.T, container string) string {
	t.Helper()
	out := dockerExecOutput(t, container, "cat", "/etc/headscale/config.yaml")
	match := baseDomainPattern.FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("dns.base_domain not found in %s's /etc/headscale/config.yaml", container)
	}
	return strings.Trim(match[1], `"'`)
}

// buildDNSProbe compiles testdata/dnsprobe into a temporary, statically
// linked linux/amd64 binary (matching the tailscale/tailscale image's
// architecture and its CGO-free Alpine base) that TestResolveStorageService_
// RealMagicDNS_RealHeadscale later copies into a real mesh-joined
// container.
func buildDNSProbe(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	out := filepath.Join(t.TempDir(), "dnsprobe")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", out,
		"github.com/Verryx-02/RAM-USB/user-client/internal/mesh/testdata/dnsprobe")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build dnsprobe: %v (output: %s)", err, output)
	}
	return out
}

// headscaleUserCreate mints a real Headscale user via the operator CLI
// (the same "docker exec ... headscale ..." approach as
// headscale_integration_test.go's mintAPIKey), returning its numeric ID.
func headscaleUserCreate(t *testing.T, container, name string) uint64 {
	t.Helper()
	out := dockerExecOutput(t, container, "headscale", "users", "create", name, "-o", "json")
	var user struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &user); err != nil {
		t.Fatalf("parsing 'headscale users create' output: %v (output: %s)", err, out)
	}
	if user.ID == 0 {
		t.Fatalf("'headscale users create' returned a zero user id (output: %s)", out)
	}
	return user.ID
}

// headscalePreAuthKeyCreate mints a real, single-use pre-auth key for
// userID, tagged with the caller-supplied ACL tag - see
// TestResolveStorageService_RealMagicDNS_RealHeadscale's own call sites for
// why this needs to be a real reachability tag (tag:storage-access/
// tag:storage-service), not just NM-F-13's membership-only tag:mesh-member.
func headscalePreAuthKeyCreate(t *testing.T, container string, userID uint64, tag string) string {
	t.Helper()
	out := dockerExecOutput(t, container, "headscale", "preauthkeys", "create",
		"--user", fmt.Sprintf("%d", userID),
		"--tags", tag,
		"--expiration", "10m",
		"-o", "json")
	var key struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(out), &key); err != nil {
		t.Fatalf("parsing 'headscale preauthkeys create' output: %v (output: %s)", err, out)
	}
	if key.Key == "" {
		t.Fatalf("'headscale preauthkeys create' returned an empty key (output: %s)", out)
	}
	return key.Key
}

// startStandinNode starts a real, disposable tailscale/tailscale container
// (this project's own deployments/compose/tailscale-test.yml pattern,
// parameterized here per-hostname) joining headscaleContainer's mesh with a
// freshly minted pre-auth key, and registers its removal via t.Cleanup.
// TS_USERSPACE=false is required - containerboot's userspace-networking
// default has no kernel tailscale0 interface at all, which leaves
// 100.100.100.100 (the MagicDNS stub resolver dnsprobe queries)
// unreachable even though the node otherwise appears joined (confirmed
// live this session; also documented at
// deployments/docker/storage-service/VERIFICATION.md).
func startStandinNode(t *testing.T, headscaleContainer, devTLSCert string, userID uint64, hostname, aclTag string) string {
	t.Helper()

	key := headscalePreAuthKeyCreate(t, headscaleContainer, userID, aclTag)
	containerName := hostname

	args := []string{
		"run", "-d", "--rm", "--name", containerName,
		"--network", "ramusb-net",
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--device", "/dev/net/tun:/dev/net/tun",
		"-v", devTLSCert + ":/usr/local/share/ca-certificates/headscale-dev.crt:ro",
		"-e", "TS_AUTHKEY=" + key,
		"-e", "TS_USERSPACE=false",
		"-e", "TS_ACCEPT_DNS=true",
		"-e", "TS_EXTRA_ARGS=--login-server=https://" + headscaleContainer + ":8080 --hostname=" + hostname + " --accept-dns=true",
		"--entrypoint", "/bin/sh",
		"tailscale/tailscale:latest",
		"-c", "update-ca-certificates && exec /usr/local/bin/containerboot",
	}
	if output, err := exec.CommandContext(context.Background(), "docker", args...).CombinedOutput(); err != nil { //nolint:gosec // fixed argv, test-only, no request input
		t.Fatalf("docker run %s: %v (output: %s)", containerName, err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() //nolint:gosec // fixed argv, test-only cleanup
	})
	return containerName
}

// waitForNodeIPv4 polls Headscale's own live node list (never the
// container's own "tailscale status", which reflects the node's local
// belief, not Headscale's authoritative view) until hostname is
// registered, returning the IPv4 address Headscale itself assigned it -
// per pkg-mesh's own established rule, this polls the control-plane view,
// never a WireGuard data-plane signal.
func waitForNodeIPv4(t *testing.T, headscaleContainer, hostname string) string {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		out, err := exec.CommandContext(context.Background(), "docker", "exec", headscaleContainer, //nolint:gosec // fixed argv, test-only
			"headscale", "nodes", "list", "-o", "json").CombinedOutput()
		if err == nil {
			var nodes []struct {
				Name        string   `json:"name"`
				IPAddresses []string `json:"ip_addresses"`
			}
			if json.Unmarshal(out, &nodes) == nil {
				for _, n := range nodes {
					if n.Name != hostname {
						continue
					}
					for _, addr := range n.IPAddresses {
						if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
							return addr
						}
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for Headscale to register node %q", hostname)
		}
		time.Sleep(1 * time.Second)
	}
}

// copyIntoContainer docker-cps src (a host path) to dst inside container.
func copyIntoContainer(t *testing.T, container, src, dst string) {
	t.Helper()
	if output, err := exec.CommandContext(context.Background(), "docker", "cp", src, container+":"+dst).CombinedOutput(); err != nil { //nolint:gosec // fixed argv, test-only
		t.Fatalf("docker cp %s %s:%s: %v (output: %s)", src, container, dst, err, output)
	}
}

// runDNSProbeWithRetry runs the copied dnsprobe binary inside container,
// retrying briefly - a real mesh node can take a few seconds after
// Headscale-side registration before its own MagicDNS view catches up.
func runDNSProbeWithRetry(t *testing.T, container, hostname string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	var lastOutput []byte
	for time.Now().Before(deadline) {
		output, err := exec.CommandContext(context.Background(), "docker", "exec", container, "/dnsprobe", hostname).CombinedOutput() //nolint:gosec // fixed argv, test-only
		if err == nil {
			return strings.TrimSpace(string(output))
		}
		lastErr, lastOutput = err, output
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("dnsprobe %q inside %s never succeeded: %v (output: %s)", hostname, container, lastErr, lastOutput)
	return ""
}

// dockerExecOutput runs "docker exec container args..." and returns its
// trimmed stdout+stderr, failing the test on a non-zero exit.
func dockerExecOutput(t *testing.T, container string, args ...string) string {
	t.Helper()
	full := append([]string{"exec", container}, args...)
	output, err := exec.CommandContext(context.Background(), "docker", full...).CombinedOutput() //nolint:gosec // fixed argv, test-only
	if err != nil {
		t.Fatalf("docker %v: %v (output: %s)", full, err, output)
	}
	return strings.TrimSpace(string(output))
}
