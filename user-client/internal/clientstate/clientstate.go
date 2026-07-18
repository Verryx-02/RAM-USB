// Package clientstate persists the one piece of state the Client needs
// across separate invocations of its CLI subcommands (register, then
// later, separately, backup/restore): the POSIX username Storage-Service
// created for this user at registration (DV-F-08/ST-F-06), which CL-F-06/
// CL-F-07's restic invocation needs to address the user's own chroot
// (SRS §4.5: /storage/user<xxxxxx>/data/).
//
// DESIGN DECISION FLAGGED FOR REVIEW: the SRS does not say the Client must
// persist anything between commands - CL-F-02/CL-F-06/CL-F-07 are each
// individually "following a user command", without specifying whether a
// single process handles the whole registration-then-backup lifecycle or
// separate invocations do. Since UC-01/UC-03 describe register and backup
// as clearly separate steps in time (register once, back up repeatedly,
// possibly days apart), this package's choice is to persist the POSIX
// username locally (alongside CL-F-01's key pair and reposecret's
// repository password, in the same os.UserConfigDir()/ram-usb directory)
// rather than requiring the user to re-type it on every backup/restore
// invocation.
package clientstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// fileName is the fixed file name this package stores the POSIX username
// under, inside the directory a caller supplies (in practice, the same
// ram-usb config directory sshkey.ConfigDir returns).
const fileName = "posix-username"

// fileMode is a conventional world-readable mode - a POSIX username
// carries no secret material.
const fileMode = 0o644

// SavePosixUsername persists username under dir, overwriting any
// previously saved value (e.g. if a user re-registers).
func SavePosixUsername(dir, username string) error {
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte(username), fileMode); err != nil {
		return fmt.Errorf("clientstate: write posix username: %w", err)
	}
	return nil
}

// LoadPosixUsername reads back the POSIX username saved under dir. It
// reports (\"\", false, nil) if no value has been saved yet - callers
// (backup/restore) should surface this as "run register first", not treat
// it as a generic I/O failure.
func LoadPosixUsername(dir string) (string, bool, error) {
	path := filepath.Join(dir, fileName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is dir (the caller's own ram-usb config directory) joined with this package's own fixed fileName constant, never externally-supplied input.
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("clientstate: read posix username: %w", err)
	}
	return strings.TrimSpace(string(raw)), true, nil
}
