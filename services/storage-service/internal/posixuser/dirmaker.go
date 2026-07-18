package posixuser

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// DirMaker abstracts the filesystem/ownership half of POSIX-user creation
// (ST-F-08's chroot-root/data-directory ownership) behind a small seam, so
// Creator's ordering and fail-secure logic can be unit-tested
// (docs/Test_Plan.md §2.1: "no network, no other service") without
// touching a real filesystem or running as root.
type DirMaker interface {
	// Mkdir creates path (and any necessary parents) if it does not
	// already exist, with the given permission mode.
	Mkdir(path string, mode os.FileMode) error

	// Chown changes path's owner (and group) to the POSIX user named
	// username.
	Chown(path, username string) error
}

// RealDirMaker is the production DirMaker: it creates real directories via
// os.MkdirAll and changes real ownership via os.Chown, resolving username
// to a uid/gid via os/user.Lookup.
//
// os.MkdirAll's mode argument, like mkdir(2), is subject to the process's
// umask (bits present in the umask are cleared from the requested mode).
// Both chrootRootMode and dataDirMode below only ever request owner/group/
// other bits that a conventional umask (022 or tighter) would leave
// untouched; this package does not itself force a specific umask.
type RealDirMaker struct{}

// chrootRootMode is the permission bits Creator.CreateUser uses for each
// user's chroot root directory. 0711 (execute for owner/group/other, no
// group/other read or write) lets the connecting POSIX user - a different
// uid than the root:root owner - traverse into the directory to reach
// their own data/ subdirectory, without making the chroot root's own
// contents listable or writable by anyone but root. See
// Creator.CreateUser's own doc comment at its Mkdir(chrootRoot, ...) call
// site for why this differs from dataDirMode.
const chrootRootMode = 0o711

// dataDirMode is the permission bits used for each user's writable data/
// subdirectory. 0700 (owner-only) matches ST-F-08's "the only writable
// space is the dedicated subdirectory inside the chroot" — no other POSIX
// user, and no group/world principal, needs any access.
const dataDirMode = 0o700

// Mkdir implements DirMaker via os.MkdirAll.
func (RealDirMaker) Mkdir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("posixuser: mkdir %s: %w", path, err)
	}
	return nil
}

// Chown implements DirMaker via os/user.Lookup + os.Chown. Because
// Creator.CreateUser explicitly runs "groupadd <username>" before "useradd
// --gid <username> <username>" (ST-F-06), the account's primary group
// always has the same name as the account itself, so looking up username
// alone is enough to get both its uid and gid — not a distribution-default
// assumption, but a direct consequence of how this package creates the
// account.
func (RealDirMaker) Chown(path, username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("posixuser: lookup user %s: %w", username, err)
	}

	uid, err := parseID(u.Uid)
	if err != nil {
		return fmt.Errorf("posixuser: parse uid %s for %s: %w", u.Uid, username, err)
	}
	gid, err := parseID(u.Gid)
	if err != nil {
		return fmt.Errorf("posixuser: parse gid %s for %s: %w", u.Gid, username, err)
	}

	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("posixuser: chown %s: %w", path, err)
	}
	return nil
}

// parseID converts a decimal uid/gid string (as returned by os/user.User's
// Uid/Gid fields) to an int suitable for os.Chown.
func parseID(s string) (int, error) {
	return strconv.Atoi(s)
}
