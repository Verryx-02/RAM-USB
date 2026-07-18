// Package posixuser implements the real OS-level half of POSIX-user
// creation (ST-F-06, ST-F-08) behind httpapi.UserCreator: shelling out to
// groupadd then useradd, then creating the chroot root and its writable
// data subdirectory per SRS §4.5's directory-structure diagram.
package posixuser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/execrunner"
)

// usernamePattern matches exactly the username shape ST-F-06 specifies:
// "user" followed by 6 lowercase base-36 characters (0-9, a-z).
// Database-Vault's DV-F-09 already generates usernames in this shape, and
// httpapi.Handler.CreateUser already re-validates it once, but this
// package re-validates it again independently rather than trusting either
// caller, per RNF-SEC-02/03 (every layer re-validates independently) and
// RD-04 (fail-secure on any uncertainty).
var usernamePattern = regexp.MustCompile(`^user[0-9a-z]{6}$`)

// storageRoot is the parent directory of every user's chroot root, per SRS
// §4.5's directory-structure diagram ("/storage/ <- root of all users").
const storageRoot = "/storage"

// rootOwner is the POSIX user (and group) that must own each user's chroot
// root directory, per SRS §4.5 ("chroot root of THIS user, owned by:
// root:root").
const rootOwner = "root"

// ErrInvalidUsername means CreateUser was called with a username that does
// not match usernamePattern.
var ErrInvalidUsername = errors.New("posixuser: username does not match the required format")

// ErrGroupaddFailed means the groupadd invocation failed. No useradd or
// directory work is attempted afterward.
var ErrGroupaddFailed = errors.New("posixuser: groupadd failed")

// ErrUseraddFailed means the useradd invocation failed, including the case
// where the POSIX user already exists. A collision on a randomly-generated
// username is a caller-side bug (DV-F-09 is expected to generate a unique
// username), not a legitimate retry path, so this is always treated as a
// failure, never silently treated as success.
var ErrUseraddFailed = errors.New("posixuser: useradd failed")

// Creator implements httpapi.UserCreator (ST-F-06, ST-F-08) via explicit
// groupadd + useradd invocations followed by chroot-directory setup.
type Creator struct {
	// Runner invokes groupadd/useradd/groupdel. Must not be nil.
	Runner execrunner.Runner

	// DirMaker creates and owns the chroot root and data directories.
	// Must not be nil.
	DirMaker DirMaker

	// Logger receives a warning if a groupdel rollback attempt itself
	// fails after a useradd failure. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// logger returns c.Logger, or slog.Default() if unset.
func (c *Creator) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// CreateUser creates a POSIX user named username on the underlying system,
// fail-secure at every step (RD-04): any failure returns a non-nil error
// immediately, with no partial-success path reported to the caller.
//
// The account is created via two explicit steps, not useradd's own
// implicit same-named-group creation: groupadd <username> first, then
// useradd --gid <username> assigning that group explicitly. This is a
// deliberate choice over relying on distribution-default behavior (e.g.
// Debian's USERGROUPS_ENAB), so the group this account belongs to is
// always exactly the one this function itself created, not an assumption
// about the base image's /etc/login.defs. If useradd fails after groupadd
// already succeeded, the orphaned group is rolled back (groupdel) before
// returning the useradd error, so a failed attempt never leaves stray
// state behind for a future retry with the same (extremely unlikely, but
// randomly-generated usernames could theoretically collide) username to
// trip over. If that rollback itself fails, it is logged but the original
// useradd error is still what's returned - a secondary cleanup failure
// must never mask the real failure (RD-04).
//
// Every argument passed to groupadd/useradd/groupdel is built from
// username alone, after re-validating it against usernamePattern - never
// from any other caller-supplied or externally-influenced value -
// mirroring the gosec G204 justification already documented in this
// project's execrunner packages (see execrunner.Real.Run's doc comment):
// shelling out with arguments derived solely from a pattern-validated
// string is this function's intended design, not an unsanitized-input
// risk.
func (c *Creator) CreateUser(ctx context.Context, username string) error {
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}

	chrootRoot := storageRoot + "/" + username
	dataDir := chrootRoot + "/data"

	// Step 1: groupadd <username>
	if out, err := c.Runner.Run(ctx, "groupadd", username); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrGroupaddFailed, bytes.TrimSpace(out), err)
	}

	// Step 2: useradd --no-create-home --home-dir /storage/<username>
	// --shell /usr/sbin/nologin --gid <username> <username>
	out, err := c.Runner.Run(ctx, "useradd",
		"--no-create-home",
		"--home-dir", chrootRoot,
		"--shell", "/usr/sbin/nologin",
		"--gid", username,
		username,
	)
	if err != nil {
		if _, rollbackErr := c.Runner.Run(ctx, "groupdel", username); rollbackErr != nil {
			c.logger().Warn("posixuser: rollback groupdel failed after useradd failure",
				"error", rollbackErr)
		}
		return fmt.Errorf("%w: %s: %w", ErrUseraddFailed, bytes.TrimSpace(out), err)
	}

	if err := c.DirMaker.Mkdir(chrootRoot); err != nil {
		return fmt.Errorf("posixuser: create chroot root: %w", err)
	}
	if err := c.DirMaker.Chown(chrootRoot, rootOwner); err != nil {
		return fmt.Errorf("posixuser: own chroot root: %w", err)
	}
	if err := c.DirMaker.Mkdir(dataDir); err != nil {
		return fmt.Errorf("posixuser: create data directory: %w", err)
	}
	if err := c.DirMaker.Chown(dataDir, username); err != nil {
		return fmt.Errorf("posixuser: own data directory: %w", err)
	}

	return nil
}
