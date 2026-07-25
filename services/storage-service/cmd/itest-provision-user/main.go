// Command itest-provision-user is test-only infrastructure, not part of
// the production Storage-Service image: it creates one real POSIX user
// inside a running Storage-Service container by calling the exact same
// posixuser.Creator code path cmd/storage-service/main.go wires into its
// production HTTP handler (execrunner.Real, posixuser.RealDirMaker) - not
// a hand-rolled substitute for groupadd/useradd/chroot setup.
//
// services/storage-service/cmd/storage-service/sshd_integration_test.go
// cross-compiles this binary for the container's own architecture,
// `docker cp`s it in, then invokes it via `docker exec ... <username>` -
// once per test user - because chroot and useradd need real Linux
// capabilities this repository's own macOS/Windows dev hosts cannot
// provide directly (see that test file's package doc comment).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/execrunner"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/posixuser"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: itest-provision-user <username>")
		os.Exit(1)
	}

	creator := &posixuser.Creator{
		Runner:   execrunner.Real{},
		DirMaker: posixuser.RealDirMaker{},
	}
	if err := creator.CreateUser(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
