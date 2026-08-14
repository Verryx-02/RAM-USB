// Command user-client is RAM-USB's native Client (SRS docs/design/diagrams/
// 02-architecture-deployment.puml marks it <<external>> - it runs on the
// user's own machine, not as a Docker container, per RISK-03). It wires
// every already-implemented user-client package into four CLI
// subcommands, one per "following a user command" requirement:
//
//   - register: CL-F-01 (generate an SSH key pair), CL-F-09 (locally
//     pre-validate), CL-F-02 (POST /api/users), CL-F-04 (join the mesh
//     with the returned pre-auth key, if Entry-Hub's response carries one -
//     see internal/entryhub's own doc note on this field's current
//     server-side gap).
//   - login: CL-F-09, CL-F-03 (POST /api/login) - a user re-runs this
//     subcommand manually before their 12-hour ACL grant expires; this
//     binary does not run a background scheduler of its own.
//   - backup <path>: CL-F-06 (restic backup over SFTP, authenticating with
//     CL-F-01's key). CL-F-05's MagicDNS resolution needs no code here -
//     it is transparent through the OS resolver once mesh-joined.
//   - restore <snapshot> --target <path>: CL-F-07 (restic restore).
//
// Every subcommand maps a locally caught pre-validation failure or an
// Entry-Hub HTTP error code to a sanitized message (CL-F-08/CL-F-09) -
// never a raw response body or internal detail printed to the terminal.
//
// DESIGN DECISIONS FLAGGED FOR REVIEW (the SRS does not fix any of these):
//   - CLI subcommand/flag naming below (register/login/backup/restore,
//     --email/--password/--entry-hub-url/--login-server/--storage-host)
//     is this session's judgment call.
//   - The password is read, in order, from --password, the RAM_USB_PASSWORD
//     environment variable, or - when stdin is an interactive terminal - an
//     echo-free prompt. Leaving both the flag and the env var unset is the
//     recommended interactive use: --password puts the password in argv,
//     where any local "ps aux" can read it. A non-interactive run with
//     neither set fails immediately instead of blocking on a prompt. This
//     precedence is a usability/security trade-off, not an SRS-specified
//     mechanism.
//   - Entry-Hub's base URL, Headscale's login-server URL, and
//     Storage-Service's mesh hostname are read from environment variables
//     (RAM_USB_ENTRY_HUB_URL, RAM_USB_HEADSCALE_URL,
//     RAM_USB_STORAGE_HOST), mirroring every other RAM-USB service's own
//     env-var configuration convention (CONTRIBUTING.md section 7's
//     cmd/<service>/main.go pattern), even though this component is not a
//     server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/user-client/internal/clientstate"
	"github.com/Verryx-02/RAM-USB/user-client/internal/entryhub"
	"github.com/Verryx-02/RAM-USB/user-client/internal/execrunner"
	"github.com/Verryx-02/RAM-USB/user-client/internal/mesh"
	"github.com/Verryx-02/RAM-USB/user-client/internal/reposecret"
	"github.com/Verryx-02/RAM-USB/user-client/internal/restic"
	"github.com/Verryx-02/RAM-USB/user-client/internal/sshkey"
)

// Env var names this entrypoint reads. See the package doc comment's
// "design decisions flagged for review" note.
const (
	envEntryHubURL   = "RAM_USB_ENTRY_HUB_URL"
	envHeadscaleURL  = "RAM_USB_HEADSCALE_URL"
	envStorageHost   = "RAM_USB_STORAGE_HOST"
	envLoginPassword = "RAM_USB_PASSWORD"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "register":
		err = runRegister(os.Args[2:], execrunner.Real{})
	case "login":
		err = runLogin(os.Args[2:])
	case "backup":
		err = runBackup(os.Args[2:], execrunner.Real{})
	case "restore":
		err = runRestore(os.Args[2:], execrunner.Real{})
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", userFacingMessage(err))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: user-client <register|login|backup|restore> [flags]")
}

// userFacingMessage implements CL-F-08/CL-F-09 at the CLI boundary: an
// *apperrors.AppError's sanitized Public message is shown as-is; a local
// pkg/validation sentinel error (CL-F-09) is safe to show directly too,
// since none of those sentinels embed the offending field's value; any
// other error (e.g. a local I/O failure) is shown via its own Error()
// text, which this binary's own code controls end to end (never a raw
// downstream response body).
func userFacingMessage(err error) string {
	var appErr *apperrors.AppError
	if errors.As(err, &appErr) {
		return appErr.Public
	}
	return err.Error()
}

// promptPassword reads a password from stdin with echo disabled, so that
// the most convenient way to supply it is also the one that leaves it out
// of both argv (visible to any local "ps aux") and the shell history. The
// prompt goes to stderr, keeping stdout free for a subcommand's own output.
// It reports ok=false, without reading anything, when stdin is not an
// interactive terminal - a scripted or piped run must fail fast rather than
// block forever on a prompt nobody can answer.
//
// It is a var so tests can drive both branches: "go test" hands its own
// stdin to a single test binary, which is a real terminal when the suite is
// run by hand, so the non-interactive path cannot be reached by relying on
// the test environment alone.
var promptPassword = func() (string, bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", false, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, fmt.Errorf("read password from terminal: %w", err)
	}
	return string(raw), true, nil
}

// resolveCredentials reads --email/--password shared by register and
// login. The password is taken from --password, then RAM_USB_PASSWORD,
// then - when stdin is an interactive terminal - an echo-free prompt; a
// non-interactive run (script, CI, pipe) with neither flag nor env var set
// is still rejected outright rather than blocking on a read.
func resolveCredentials(fs *flag.FlagSet, args []string) (string, string, error) {
	emailFlag := fs.String("email", "", "account email address")
	passwordFlag := fs.String("password", "", "account password (or set "+envLoginPassword+", or leave both unset to be prompted)")
	if err := fs.Parse(args); err != nil {
		return "", "", err
	}

	if *emailFlag == "" {
		return "", "", fmt.Errorf("--email is required")
	}

	password := *passwordFlag
	if password == "" {
		password = os.Getenv(envLoginPassword)
	}
	if password == "" {
		prompted, ok, err := promptPassword()
		if err != nil {
			return "", "", err
		}
		if ok {
			password = prompted
		}
	}
	if password == "" {
		return "", "", fmt.Errorf("--password or %s is required", envLoginPassword)
	}
	return *emailFlag, password, nil
}

// runRegister implements CL-F-01/CL-F-02/CL-F-04/CL-F-09. runner is the
// execrunner.Runner used for the CL-F-04 "tailscale up" invocation - main()
// passes execrunner.Real{}, a test passes an execrunner.Fake, so this
// function's mesh.Join call is exercisable without a real tailscale binary.
func runRegister(args []string, runner execrunner.Runner) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	email, password, err := resolveCredentials(fs, args)
	if err != nil {
		return err
	}

	dir, err := sshkey.ConfigDir()
	if err != nil {
		return fmt.Errorf("prepare local config directory: %w", err)
	}

	keyPair, err := sshkey.EnsureKeyPair(dir)
	if err != nil {
		return fmt.Errorf("generate ssh key pair: %w", err)
	}

	entryHubURL := os.Getenv(envEntryHubURL)
	if entryHubURL == "" {
		return fmt.Errorf("%s is required", envEntryHubURL)
	}

	client := entryhub.New(entryHubURL)
	result, err := client.Register(context.Background(), validation.RegisterRequest{
		Email:        email,
		Password:     password,
		SSHPublicKey: keyPair.AuthorizedKeysLine,
	})
	if err != nil {
		return err
	}

	if err := clientstate.SavePosixUsername(dir, result.PosixUsername); err != nil {
		return fmt.Errorf("save posix username locally: %w", err)
	}
	fmt.Printf("registered successfully as %s\n", result.PosixUsername)

	if result.PreauthKey == "" {
		fmt.Println("no tailscale pre-auth key was returned; join the mesh manually before backing up or restoring")
		return nil
	}

	loginServer := os.Getenv(envHeadscaleURL)
	if loginServer == "" {
		fmt.Printf("%s is not set; skipping automatic mesh join - run 'tailscale up --login-server=<headscale-url> --authkey=%s' manually\n", envHeadscaleURL, result.PreauthKey)
		return nil
	}

	if err := mesh.Join(context.Background(), runner, loginServer, result.PreauthKey); err != nil {
		return fmt.Errorf("join mesh network: %w", err)
	}
	fmt.Println("joined the mesh network successfully")
	return nil
}

// runLogin implements CL-F-03/CL-F-09.
func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	email, password, err := resolveCredentials(fs, args)
	if err != nil {
		return err
	}

	entryHubURL := os.Getenv(envEntryHubURL)
	if entryHubURL == "" {
		return fmt.Errorf("%s is required", envEntryHubURL)
	}

	client := entryhub.New(entryHubURL)
	if err := client.Login(context.Background(), validation.LoginRequest{Email: email, Password: password}); err != nil {
		return err
	}
	fmt.Println("login succeeded")
	return nil
}

// resticConfig builds the shared restic.Config backup and restore both
// need: the local key pair, the persisted POSIX username from a prior
// register, the repository password, and the Storage-Service mesh
// hostname. runner is the execrunner.Runner the returned Config invokes
// "restic" through - main() passes execrunner.Real{}, a test passes an
// execrunner.Fake.
func resticConfig(runner execrunner.Runner) (restic.Config, error) {
	dir, err := sshkey.ConfigDir()
	if err != nil {
		return restic.Config{}, fmt.Errorf("prepare local config directory: %w", err)
	}

	keyPair, ok, err := sshkey.Load(dir)
	if err != nil {
		return restic.Config{}, fmt.Errorf("load ssh key pair: %w", err)
	}
	if !ok {
		return restic.Config{}, fmt.Errorf("no ssh key pair found; run 'register' first")
	}

	posixUsername, ok, err := clientstate.LoadPosixUsername(dir)
	if err != nil {
		return restic.Config{}, fmt.Errorf("load posix username: %w", err)
	}
	if !ok {
		return restic.Config{}, fmt.Errorf("no posix username found; run 'register' first")
	}

	host := os.Getenv(envStorageHost)
	if host == "" {
		return restic.Config{}, fmt.Errorf("%s is required", envStorageHost)
	}

	password, err := reposecret.Ensure(dir)
	if err != nil {
		return restic.Config{}, fmt.Errorf("prepare repository password: %w", err)
	}

	return restic.Config{
		Runner:             runner,
		Host:               host,
		PosixUsername:      posixUsername,
		PrivateKeyPath:     keyPair.PrivateKeyPath,
		RepositoryPassword: password,
	}, nil
}

// runBackup implements CL-F-06. runner is the execrunner.Runner used for
// the restic invocations - see resticConfig's own doc comment.
func runBackup(args []string, runner execrunner.Runner) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: user-client backup <path>")
	}
	localPath := fs.Arg(0)

	cfg, err := resticConfig(runner)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := restic.Init(ctx, cfg); err != nil {
		return fmt.Errorf("initialize repository: %w", err)
	}
	if err := restic.Backup(ctx, cfg, localPath); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	fmt.Println("backup completed successfully")
	return nil
}

// runRestore implements CL-F-07. runner is the execrunner.Runner used for
// the restic invocations - see resticConfig's own doc comment.
func runRestore(args []string, runner execrunner.Runner) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	target := fs.String("target", "", "local directory to restore into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: user-client restore <snapshot> --target <path>")
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}
	snapshotID := fs.Arg(0)

	cfg, err := resticConfig(runner)
	if err != nil {
		return err
	}

	if err := restic.Restore(context.Background(), cfg, snapshotID, *target); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	fmt.Println("restore completed successfully")
	return nil
}
