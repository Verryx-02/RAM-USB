package restic

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// knownHostsFileName is the fixed file name WriteKnownHosts stores Storage-
// Service's pinned SSH host key under, inside the caller's own ram-usb
// config directory (sshkey.ConfigDir()).
const knownHostsFileName = "known_hosts"

// knownHostsFileMode is a conventional world-readable mode - a known_hosts
// entry carries a public key, not a secret.
const knownHostsFileMode = 0o644

// WriteKnownHosts implements CL-F-11: writes a known_hosts file under dir
// containing a single entry for host's pinned SSH host public key
// (hostPublicKeyLine, as returned by Entry-Hub's registration response and
// persisted via clientstate.SaveHostPublicKey - an authorized_keys-style
// "<keytype> <base64> [comment]" line, ST-F-16), and returns the written
// file's path.
//
// Because Storage-Service's sshd listens on the non-default SSHPort
// (ST-F-03), the entry uses OpenSSH's bracketed "[host]:port" hostname
// form (sshd(8), "SSH_KNOWN_HOSTS FILE FORMAT") rather than a bare
// hostname - a bare-hostname entry is only ever matched against the
// default port 22 and would never match a connection to SSHPort, causing
// ssh to treat the pinned key as unknown and still fail closed (safe, but
// not what CL-F-11 intends).
func WriteKnownHosts(dir, host, hostPublicKeyLine string) (string, error) {
	fields := strings.Fields(hostPublicKeyLine)
	if len(fields) < 2 {
		return "", fmt.Errorf("restic: malformed stored ssh host public key: %q", hostPublicKeyLine)
	}
	entry := fmt.Sprintf("[%s]:%d %s %s\n", host, SSHPort, fields[0], fields[1])

	path := filepath.Join(dir, knownHostsFileName)
	if err := os.WriteFile(path, []byte(entry), knownHostsFileMode); err != nil {
		return "", fmt.Errorf("restic: write known_hosts: %w", err)
	}
	return path, nil
}
