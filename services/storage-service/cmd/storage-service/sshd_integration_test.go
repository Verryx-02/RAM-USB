package main

// sshd_integration_test.go verifies ST-F-03, ST-F-04, ST-F-05, ST-F-07,
// ST-F-09 against a REAL running sshd, driven by the REAL
// deployments/docker/storage-service/sshd_config and REAL POSIX users
// created through the actual posixuser.Creator.CreateUser code path (via
// the itest-provision-user helper, see that command's own package doc
// comment) - not a static check that the right directive string is
// present in the config file. Every requirement below is exercised by
// actually attempting the action it forbids (or requires) and observing
// the real rejection or success, over a real SSH/SFTP connection.
//
// ST-F-02 (client-side encryption) is deliberately not covered here:
// server-side sshd never sees plaintext content by construction, so there
// is nothing to attempt to violate - confirmed with the user.
//
// This builds the real deployments/docker/storage-service/Dockerfile
// image and drives it directly via the Docker CLI, skipping s6-overlay's
// tailscaled dependency (this test exercises sshd's own hardening, not
// NET-F-01's mesh-only reachability, a separate, already-covered
// concern) - same "_Real..._"-named, skip-cleanly-without-Docker
// philosophy as this package's own TestBuildServerTLSConfig_RealCA_*
// tests and metrics-collector/cmd/metrics-collector/
// main_integration_test.go's TestMetricsPipeline_RealBroker_RealTimescaleDB_*.
//
// Keys are supplied through the SAME mechanism production uses,
// AuthorizedKeysCommand (ST-F-11): sshd_config sets "AuthorizedKeysFile
// none", so a key file under a user's chroot is not a credential source at
// all any more, by design. What this test substitutes is only the far end
// of that command - the real /usr/local/bin/authorized-keys-command binary
// is replaced in the throwaway container by a stub script that echoes back
// a fixture keyed by the %u sshd passes it (see installStubAuthorizedKeysCommand).
// sshd's own invocation path (AuthorizedKeysCommandUser sshd-authkeys,
// argument expansion, exit-status handling, fail-closed on no output) is
// therefore exercised exactly as in production; only Database-Vault and
// the mTLS round trip behind it are stubbed out, since standing up
// Database-Vault/Certificate-Authority just to authenticate two SFTP
// sessions would test that requirement's own network wiring rather than
// sshd's hardening.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	// sshdDockerfile/sshdBuildContext are relative to this test file's own
	// package directory (services/storage-service/cmd/storage-service),
	// which is also `go test`'s working directory.
	sshdDockerfile   = "../../../../deployments/docker/storage-service/Dockerfile"
	sshdBuildContext = "../../../.."
	sshdImageTag     = "ram-usb/storage-service-sshd-itest:latest"

	// sshdUserA/sshdUserB match ST-F-06's fixed "user<xxxxxx>" shape
	// (^user[0-9a-z]{6}$) that posixuser.Creator itself re-validates.
	sshdUserA = "userstfa1a"
	sshdUserB = "userstfb2b"

	// authorizedKeysCommandPath is the exact path the production
	// sshd_config names in its AuthorizedKeysCommand directive; the
	// stub overwrites the binary there rather than changing the config,
	// so the config under test stays the real one.
	authorizedKeysCommandPath = "/usr/local/bin/authorized-keys-command"
	stubAuthorizedKeysDir     = "/etc/ssh/itest-authorized-keys"

	dockerCommandTimeout = 30 * time.Second
)

// skipUnlessDockerAvailable skips cleanly (not fails) when Docker is not
// installed or its daemon is not reachable, same convention as this
// package's own skipUnlessCAConfigured and metrics-collector's
// skipUnlessCAConfigured-style helpers.
func skipUnlessDockerAvailable(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil { //nolint:noctx // ctx already bounds this call
		t.Skipf("docker daemon not reachable: %v", err)
	}
}

// buildSSHDImage builds the real production image from its own
// Dockerfile, exactly as deployments/docker/storage-service/
// VERIFICATION.md's own procedure does. Docker's build cache makes every
// run after the first one fast; only a first-ever run pays for the
// s6-overlay/tailscale release downloads baked into that Dockerfile.
func buildSSHDImage(ctx context.Context, t *testing.T) {
	t.Helper()

	// Absolute paths: `docker build`'s -f flag, when relative, resolves
	// against the build context directory, not the CLI's own working
	// directory - confirmed empirically - so passing both paths relative
	// to this test's own working directory only works if converted to
	// absolute first.
	dockerfile, err := filepath.Abs(sshdDockerfile)
	if err != nil {
		t.Fatalf("filepath.Abs(%s): %v", sshdDockerfile, err)
	}
	buildContext, err := filepath.Abs(sshdBuildContext)
	if err != nil {
		t.Fatalf("filepath.Abs(%s): %v", sshdBuildContext, err)
	}

	buildCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(buildCtx, "docker", "build", //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
		"-f", dockerfile, "-t", sshdImageTag, buildContext)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

// sshdContainer is the running throwaway container this test drives real
// SSH/SFTP connections against.
type sshdContainer struct {
	name    string
	sshPort int
}

// startSSHDContainer runs the real image directly (bypassing s6-overlay's
// /init entrypoint and its tailscaled dependency - see this file's own
// package doc comment for why), under the same minimal capability set
// deployments/compose/storage-service.yml grants sshd/posixuser
// themselves (CHOWN/SETUID/SETGID/SYS_CHROOT), then starts sshd by hand
// exactly the way rootfs/etc/s6-overlay/s6-rc.d/sshd-hostkeys and sshd's
// own longrun would (ssh-keygen -A, then sshd itself - sshd daemonizes on
// its own without -D).
func startSSHDContainer(ctx context.Context, t *testing.T) *sshdContainer {
	t.Helper()

	name := fmt.Sprintf("ss-sshd-itest-%d", time.Now().UnixNano())

	runCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	runCmd := exec.CommandContext(runCtx, "docker", "run", "-d", "--rm", //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
		"--name", name,
		"--cap-drop", "ALL",
		"--cap-add", "CHOWN",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "SYS_CHROOT",
		"--entrypoint", "sleep",
		"-p", "127.0.0.1::2222",
		sshdImageTag, "infinity")
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { //nolint:contextcheck // deliberately context.Background() below, not the enclosing ctx, so this cleanup still runs the container removal even if the test's own ctx is already cancelled/expired by the time t.Cleanup runs
		_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run() //nolint:gosec // fixed argv, test-only cleanup
	})

	dockerExec(ctx, t, name, "mkdir", "-p", "-m", "0755", "/run/sshd")
	dockerExec(ctx, t, name, "ssh-keygen", "-A")
	dockerExec(ctx, t, name, "/usr/sbin/sshd")

	return &sshdContainer{name: name, sshPort: hostPort(ctx, t, name, "2222/tcp")}
}

// dockerExec runs `docker exec <container> <args...>`, failing the test
// immediately on a nonzero exit - every call site here is test setup that
// must succeed for the rest of the test to mean anything, not behavior
// under test itself.
func dockerExec(ctx context.Context, t *testing.T, container string, args ...string) string {
	t.Helper()

	execCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()

	full := append([]string{"exec", container}, args...)
	out, err := exec.CommandContext(execCtx, "docker", full...).CombinedOutput() //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
	if err != nil {
		t.Fatalf("docker exec %s %v: %v\n%s", container, args, err, out)
	}
	return string(out)
}

// hostPort resolves the ephemeral host port Docker mapped to
// containerPort (e.g. "2222/tcp"), via `docker port`.
func hostPort(ctx context.Context, t *testing.T, container, containerPort string) int {
	t.Helper()

	portCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()

	out, err := exec.CommandContext(portCtx, "docker", "port", container, containerPort).Output() //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
	if err != nil {
		t.Fatalf("docker port %s %s: %v", container, containerPort, err)
	}

	_, portStr, err := net.SplitHostPort(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("docker port %s %s: unexpected output %q: %v", container, containerPort, out, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("docker port %s %s: non-numeric port %q: %v", container, containerPort, portStr, err)
	}
	return port
}

// dockerServerArch reports the Docker daemon's own architecture
// (e.g. "arm64", "amd64") - the GOARCH buildProvisionHelper must
// cross-compile itest-provision-user for, since it runs inside a
// container on that same daemon, which may differ from the host running
// `go test` (e.g. Docker Desktop's Linux VM vs. a macOS host).
func dockerServerArch(ctx context.Context, t *testing.T) string {
	t.Helper()

	archCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()

	out, err := exec.CommandContext(archCtx, "docker", "version", "--format", "{{.Server.Arch}}").Output() //nolint:noctx // ctx already bounds this call
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// buildProvisionHelper cross-compiles itest-provision-user (this
// package's sibling cmd, see its own package doc comment) for the Docker
// daemon's architecture, returning the built binary's host path.
func buildProvisionHelper(ctx context.Context, t *testing.T) string {
	t.Helper()

	arch := dockerServerArch(ctx, t)
	binPath := filepath.Join(t.TempDir(), "itest-provision-user")

	buildCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(buildCtx, "go", "build", "-o", binPath, "../itest-provision-user") //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build itest-provision-user: %v\n%s", err, out)
	}
	return binPath
}

// copyIntoContainer runs `docker cp hostPath <container>:<containerPath>`.
func copyIntoContainer(ctx context.Context, t *testing.T, container, hostPath, containerPath string) {
	t.Helper()

	cpCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	if out, err := exec.CommandContext(cpCtx, "docker", "cp", hostPath, container+":"+containerPath).CombinedOutput(); err != nil { //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
		t.Fatalf("docker cp %s %s:%s: %v\n%s", hostPath, container, containerPath, err, out)
	}
}

// generateSSHKeyPair returns a fresh Ed25519 keypair as an ssh.Signer (for
// dialing) and its authorized_keys-formatted line (for installing on the
// server side).
func generateSSHKeyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(sshPub))
}

// writeFileInContainer writes content to containerPath inside container
// (as root, the container's only usable identity here) and sets mode on
// it. Order matters throughout this file: chmod runs BEFORE any chown, not
// after. This container's capability set (CHOWN/SETUID/SETGID/SYS_CHROOT
// only, no CAP_FOWNER/CAP_DAC_OVERRIDE) means root can chmod a file it
// still owns, but loses the ability to chmod it at all the instant chown
// hands ownership to a different POSIX user - confirmed empirically
// against this exact image.
func writeFileInContainer(ctx context.Context, t *testing.T, container, containerPath, content, mode string) {
	t.Helper()

	writeCtx, cancel := context.WithTimeout(ctx, dockerCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(writeCtx, "docker", "exec", "-i", container, //nolint:noctx,gosec // ctx already bounds this call; fixed argv, test-only
		"sh", "-c", "cat > "+containerPath)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write %s: %v\n%s", containerPath, err, out)
	}
	dockerExec(ctx, t, container, "chmod", mode, containerPath)
}

// installStubAuthorizedKeysCommand replaces the real
// /usr/local/bin/authorized-keys-command (which would call Database-Vault
// over mTLS) with a stub returning the fixture registered for the username
// sshd passes as %u, and creates the fixture directory those keys live in.
//
// Everything on sshd's own side of ST-F-11 stays real: the same
// AuthorizedKeysCommand path from the production sshd_config, run as the
// same unprivileged AuthorizedKeysCommandUser (sshd-authkeys), with the
// same fail-closed contract - a username with no fixture makes `cat` exit
// nonzero and sshd offers no key at all, exactly as a Database-Vault
// lookup failure would (RD-04).
//
// Location: /etc/ssh (root-owned), not /etc/storage-service (owned by
// sshd-authkeys per the Dockerfile) - without CAP_DAC_OVERRIDE, root
// cannot create entries inside a directory it does not own. Mode 0755/0644
// so the unprivileged sshd-authkeys account can read the fixtures back.
func installStubAuthorizedKeysCommand(ctx context.Context, t *testing.T, container string) {
	t.Helper()

	dockerExec(ctx, t, container, "mkdir", "-p", "-m", "0755", stubAuthorizedKeysDir)

	const stub = `#!/bin/sh
# Test-only stand-in for ST-F-11's real authorized-keys-command: sshd
# passes the connecting username as $1 (%u in sshd_config). Missing
# fixture -> cat exits nonzero, no key is printed, sshd denies the
# connection, same fail-closed outcome as a Database-Vault lookup error.
set -eu
exec cat "` + stubAuthorizedKeysDir + `/$1"
`
	writeFileInContainer(ctx, t, container, authorizedKeysCommandPath, stub, "0755")
}

// registerAuthorizedKey makes authorizedKeyLine the key the stub
// AuthorizedKeysCommand returns for username - the test-side equivalent of
// that user's public key being registered in Database-Vault.
func registerAuthorizedKey(ctx context.Context, t *testing.T, container, username, authorizedKeyLine string) {
	t.Helper()

	writeFileInContainer(ctx, t, container, stubAuthorizedKeysDir+"/"+username, authorizedKeyLine, "0644")
}

// dialSSHDContainer opens a real SSH connection to c, authenticating as
// user with signer. hostKeyCallback is InsecureIgnoreHostKey: the
// container's host keys are freshly generated per test run (ssh-keygen -A
// above) and never persisted, so there is no known-hosts baseline to
// pin - appropriate for this throwaway test container only, never
// production code.
func dialSSHDContainer(c *sshdContainer, user string, signer ssh.Signer) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test-only, host key is freshly generated per run
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("localhost:%d", c.sshPort), config)
}

// Requirement: ST-F-03
// Requirement: ST-F-04
// Requirement: ST-F-05
// Requirement: ST-F-07
// Requirement: ST-F-09
//
// Against one real running sshd (real sshd_config, real POSIX users, real
// chroots), this test actually attempts each requirement's violation and
// confirms sshd rejects it - never a static check of the config file's
// own directive strings.
//
// Wall-clock budget (KI-21): the docker build + container start + helper
// cross-compile + multiple sequential real SSH/SFTP round trips this test
// drives have been observed to take anywhere from ~45s to ~115s on the
// same machine back to back, purely from Docker daemon/build-cache load
// variance - there is no deadlock in this file (every exec.Cmd call here
// uses CombinedOutput/Output, which os/exec already drains stdout+stderr
// concurrently; never StdoutPipe/StderrPipe read sequentially). Pass
// `-timeout` of at least 180s when running this test standalone; a tighter
// external timeout (e.g. 120s) can abort a still-progressing, slow-but-not-
// stuck run and look like a hang.
func TestStorageServiceSSHD_RealContainer_EnforcesHardening(t *testing.T) {
	skipUnlessDockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	buildSSHDImage(ctx, t)
	c := startSSHDContainer(ctx, t)

	helperBin := buildProvisionHelper(ctx, t)
	copyIntoContainer(ctx, t, c.name, helperBin, "/usr/local/bin/itest-provision-user")

	// Two real POSIX users, via the actual posixuser.Creator.CreateUser
	// code path (see itest-provision-user's own package doc comment) -
	// not a hand-rolled useradd/chroot substitute.
	dockerExec(ctx, t, c.name, "/usr/local/bin/itest-provision-user", sshdUserA)
	dockerExec(ctx, t, c.name, "/usr/local/bin/itest-provision-user", sshdUserB)

	installStubAuthorizedKeysCommand(ctx, t, c.name)

	signerA, authorizedKeyLineA := generateSSHKeyPair(t)
	// signerB is userB's own real, registered key - never registered for
	// sshdUserA, so it also doubles as ST-F-03's "unregistered key" case
	// when presented as sshdUserA below.
	signerB, authorizedKeyLineB := generateSSHKeyPair(t)
	// signerRoot is registered for root, so the root subtest below is
	// rejected by sshd's own account policy and not merely by the absence
	// of a usable key.
	signerRoot, authorizedKeyLineRoot := generateSSHKeyPair(t)

	registerAuthorizedKey(ctx, t, c.name, sshdUserA, authorizedKeyLineA)
	registerAuthorizedKey(ctx, t, c.name, sshdUserB, authorizedKeyLineB)
	registerAuthorizedKey(ctx, t, c.name, "root", authorizedKeyLineRoot)

	// A marker file inside user B's own data/ directory - real content
	// this test attempts (and must fail) to reach from user A's session
	// (ST-F-05). dataDir is owner-only (0700, see posixuser.dataDirMode's
	// own doc comment), and this container's capability set has no
	// CAP_DAC_OVERRIDE, so root itself cannot write there directly - the
	// file is created for real over user B's own authenticated SFTP
	// session instead.
	func() {
		client, err := dialSSHDContainer(c, sshdUserB, signerB)
		if err != nil {
			t.Fatalf("ssh.Dial as user B (test setup) = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			t.Fatalf("sftp.NewClient as user B (test setup) = %v, want nil", err)
		}
		defer func() { _ = sftpClient.Close() }()

		f, err := sftpClient.Create("data/secret.txt")
		if err != nil {
			t.Fatalf("Create(data/secret.txt) as user B (test setup) = %v, want nil", err)
		}
		if _, err := f.Write([]byte("userB-secret")); err != nil {
			t.Fatalf("Write (test setup) = %v, want nil", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close (test setup) = %v, want nil", err)
		}
	}()

	t.Run("ST-F-03_registered_key_grants_sftp_access", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial with registered key = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			t.Fatalf("sftp.NewClient = %v, want nil", err)
		}
		defer func() { _ = sftpClient.Close() }()

		// ReadDir(".") (the chroot root itself, owned root:root 0711 - see
		// posixuser.chrootRootMode's own doc comment) is deliberately not
		// listable by the connecting user, by design: only "data/" is.
		if _, err := sftpClient.ReadDir("data"); err != nil {
			t.Fatalf("ReadDir(data) = %v, want nil", err)
		}

		content := []byte("ST-F-03 round-trip content")
		f, err := sftpClient.Create("data/roundtrip.txt")
		if err != nil {
			t.Fatalf("Create(data/roundtrip.txt) = %v, want nil", err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatalf("Write = %v, want nil", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}

		got, err := sftpClient.Open("data/roundtrip.txt")
		if err != nil {
			t.Fatalf("Open(data/roundtrip.txt) = %v, want nil", err)
		}
		defer func() { _ = got.Close() }()
		gotContent, err := io.ReadAll(got)
		if err != nil {
			t.Fatalf("ReadAll = %v, want nil", err)
		}
		if !bytes.Equal(gotContent, content) {
			t.Fatalf("round-tripped content = %q, want %q", gotContent, content)
		}
	})

	t.Run("ST-F-03_unregistered_key_denied", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerB)
		if err == nil {
			_ = client.Close()
			t.Fatal("ssh.Dial with an unregistered key error = nil, want an authentication failure")
		}
	})

	t.Run("ST-F-04_shell_session_denied", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession = %v, want nil", err)
		}
		defer func() { _ = session.Close() }()

		// ForceCommand internal-sftp forces sshd to run internal-sftp
		// instead of any shell, for every session on this connection -
		// including a plain interactive shell request. sshd's own
		// documented behavior for that mismatch is to refuse the session
		// outright ("This service allows sftp connections only.") and
		// exit nonzero, not silently substitute internal-sftp underneath
		// an interactive shell.
		if err := session.Shell(); err != nil {
			return // request itself already rejected
		}
		if err := session.Wait(); err == nil {
			t.Fatal("shell session Wait() error = nil, want sshd to refuse the non-sftp session")
		}
	})

	t.Run("ST-F-04_exec_command_denied", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession = %v, want nil", err)
		}
		defer func() { _ = session.Close() }()

		var stdout bytes.Buffer
		session.Stdout = &stdout
		err = session.Run("id")
		if err == nil {
			t.Fatal("Run(\"id\") error = nil, want sshd to refuse the non-sftp session")
		}
		if strings.Contains(stdout.String(), "uid=") {
			t.Fatalf("Run(\"id\") stdout = %q, want no real command output", stdout.String())
		}
	})

	t.Run("ST-F-04_tcp_forwarding_denied", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		// A direct-tcpip channel open is exactly what a local (-L) port
		// forward performs once traffic actually arrives - AllowTcpForwarding
		// no must refuse the channel itself, not merely decline to route
		// traffic through it.
		if conn, err := client.Dial("tcp", "127.0.0.1:80"); err == nil {
			_ = conn.Close()
			t.Fatal("client.Dial (direct-tcpip) error = nil, want administratively prohibited")
		}
	})

	t.Run("ST-F-04_only_sftp_subsystem_succeeds", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			t.Fatalf("sftp.NewClient (subsystem request) = %v, want nil", err)
		}
		defer func() { _ = sftpClient.Close() }()

		if _, err := sftpClient.Getwd(); err != nil {
			t.Fatalf("Getwd = %v, want nil", err)
		}
	})

	t.Run("ST-F-05_cannot_reach_other_users_directory", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			t.Fatalf("sftp.NewClient = %v, want nil", err)
		}
		defer func() { _ = sftpClient.Close() }()

		otherUserPaths := []string{
			"/storage/" + sshdUserB + "/data/secret.txt",
			"/storage/" + sshdUserB,
			"../../storage/" + sshdUserB + "/data/secret.txt",
		}
		for _, p := range otherUserPaths {
			if _, err := sftpClient.Stat(p); err == nil {
				t.Fatalf("Stat(%q) error = nil, want user A unable to see user B's directory", p)
			}
			if f, err := sftpClient.Open(p); err == nil {
				_ = f.Close()
				t.Fatalf("Open(%q) error = nil, want user A unable to read user B's directory", p)
			}
		}
	})

	t.Run("ST-F-07_cannot_escape_chroot", func(t *testing.T) {
		client, err := dialSSHDContainer(c, sshdUserA, signerA)
		if err != nil {
			t.Fatalf("ssh.Dial = %v, want nil", err)
		}
		defer func() { _ = client.Close() }()

		sftpClient, err := sftp.NewClient(client)
		if err != nil {
			t.Fatalf("sftp.NewClient = %v, want nil", err)
		}
		defer func() { _ = sftpClient.Close() }()

		// "/" itself is deliberately not in this list: it is the chroot
		// root, i.e. the confinement boundary itself, not outside it -
		// Stat("/") succeeding just confirms the connecting user can see
		// the top of their own jail, not an escape from it.
		traversalPaths := []string{
			"../../etc/passwd",
			"/etc/shadow",
			"/etc/passwd",
		}
		for _, p := range traversalPaths {
			if _, err := sftpClient.Stat(p); err == nil {
				t.Fatalf("Stat(%q) error = nil, want confinement inside the chroot", p)
			}
			if f, err := sftpClient.Open(p); err == nil {
				_ = f.Close()
				t.Fatalf("Open(%q) error = nil, want confinement inside the chroot", p)
			}
			if _, err := sftpClient.ReadDir(p); err == nil {
				t.Fatalf("ReadDir(%q) error = nil, want confinement inside the chroot", p)
			}
		}
	})

	t.Run("ST-F-09_password_authentication_denied", func(t *testing.T) {
		config := &ssh.ClientConfig{
			User:            sshdUserA,
			Auth:            []ssh.AuthMethod{ssh.Password("irrelevant")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test-only, host key is freshly generated per run
			Timeout:         10 * time.Second,
		}
		if client, err := ssh.Dial("tcp", fmt.Sprintf("localhost:%d", c.sshPort), config); err == nil {
			_ = client.Close()
			t.Fatal("ssh.Dial with password auth error = nil, want PasswordAuthentication no to reject it")
		}
	})

	t.Run("ST-F-09_root_login_denied", func(t *testing.T) {
		// Public-key auth, with a key the AuthorizedKeysCommand actually
		// returns for root: a password attempt here would only re-prove
		// PasswordAuthentication no (already covered by the subtest
		// above) and would pass identically with root logins wide open.
		// Presenting a genuinely usable root key means the only thing
		// that can reject this connection is sshd's account policy -
		// AllowUsers user* (root does not match the glob) and
		// PermitRootLogin no behind it, two independent denials.
		if client, err := dialSSHDContainer(c, "root", signerRoot); err == nil {
			_ = client.Close()
			t.Fatal("ssh.Dial as root with a registered key error = nil, want root logins rejected")
		}
	})

	t.Run("ST-F-04_non_matching_account_denied", func(t *testing.T) {
		// sshd-authkeys is a real, existing account in this image (the
		// AuthorizedKeysCommandUser) that does not match the
		// "Match User user*" block, so no directive inside that block
		// applies to it. Asserted here as an outcome, not as proof of one
		// specific directive: AllowUsers user* denies it, and so
		// independently does its "!"-locked shadow entry (useradd
		// --system sets no password). Both are deliberate; what must
		// never happen is a usable session.
		signer, authorizedKeyLine := generateSSHKeyPair(t)
		registerAuthorizedKey(ctx, t, c.name, "sshd-authkeys", authorizedKeyLine)

		if client, err := dialSSHDContainer(c, "sshd-authkeys", signer); err == nil {
			_ = client.Close()
			t.Fatal("ssh.Dial as sshd-authkeys error = nil, want AllowUsers user* to reject a non-matching account")
		}
	})
}
