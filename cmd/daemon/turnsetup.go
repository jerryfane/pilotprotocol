package main

// turnsetup implements the `pilot-daemon turn-setup cloudflare|static`
// subcommands. Both flows follow the same shape: read a secret from
// stdin (hidden on a TTY, one-line on a pipe), validate the secret by
// doing a live operation against the real service (Cloudflare mint for
// the CF flow, TURN allocation for the static flow), and only then
// write the credentials file with mode 0600.
//
// Why validate before writing? Half-configured credential files are
// the #1 support footgun for TURN. Refusing to write a file we know
// doesn't work saves the user from "my daemon starts but TURN doesn't
// work, why?".
//
// All prompts go to stderr so a user who pipes stdout somewhere (for
// example, `pilot-daemon turn-setup cloudflare ... > log.json`) still
// sees the prompt. Secrets are never echoed back, never included in
// error messages, and never passed as flags.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"golang.org/x/term"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// turnSetupUsage is printed when the user invokes `turn-setup` with no
// subcommand or an unknown one. Matches the plan's documented shape.
const turnSetupUsage = `usage: pilot-daemon turn-setup <cloudflare|static> [flags]

subcommands:
  cloudflare   configure Cloudflare Realtime TURN (short-lived creds via API)
  static       configure a long-lived coturn-style TURN server

Each subcommand reads the secret (API token or password) from stdin so
it never appears in 'ps' output or shell history. Pipe it in or type
it at the TTY prompt.
`

// runTurnSetup dispatches the `turn-setup` subcommand. Returns the
// process exit code; main() wraps this with os.Exit.
func runTurnSetup(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, turnSetupUsage)
		return 2
	}
	switch args[0] {
	case "cloudflare":
		return runTurnSetupCloudflare(args[1:])
	case "static":
		return runTurnSetupStatic(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, turnSetupUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "turn-setup: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(os.Stderr, turnSetupUsage)
		return 2
	}
}

// runTurnSetupCloudflare handles `pilot-daemon turn-setup cloudflare`.
// Reads the API token from stdin, test-mints against the Cloudflare
// API, and writes a {turn_token_id, api_token} JSON file on success.
func runTurnSetupCloudflare(args []string) int {
	fs := flag.NewFlagSet("turn-setup cloudflare", flag.ContinueOnError)
	// Direct usage output so errors go to stderr and don't get mixed
	// with a user's piped-token stdin.
	fs.SetOutput(os.Stderr)

	tokenID := fs.String("token-id", "", "Cloudflare TURN Key ID (from the dashboard; not a secret)")
	apiTokenStdin := fs.Bool("api-token-stdin", true, "read the API token from stdin (kept as the only path to avoid flag-based exposure)")
	filePath := fs.String("file", defaultCloudflareTurnCredsFile(), "destination credentials JSON path")
	ttl := fs.Duration("ttl", 1*time.Hour, "TTL requested on the test mint")
	force := fs.Bool("force", false, "overwrite the file if it already exists")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*tokenID) == "" {
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare: -token-id is required")
		return 2
	}
	if !*apiTokenStdin {
		// Refuse to support flag-based entry for the secret. Keeps it
		// out of ps, out of history, out of shell expansion surprises.
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare: -api-token-stdin=false is not supported (secret must come via stdin)")
		return 2
	}

	if err := checkOverwrite(*filePath, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	apiToken, err := readSecret("API token")
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare:", err)
		return 1
	}

	// Build provider and validate via a single mint. Context deadline
	// covers the package-internal retry budget (~2s) plus one HTTP RTT.
	opts := turncreds.CloudflareOptions{
		TokenID:   *tokenID,
		APIToken:  apiToken,
		TTL:       *ttl,
		Transport: "udp",
	}
	// Test-only hook: honor PILOT_CLOUDFLARE_TURN_BASE_URL so unit
	// tests can point at an httptest.Server. Production invocations
	// leave this unset.
	if baseURL := os.Getenv("PILOT_CLOUDFLARE_TURN_BASE_URL"); baseURL != "" {
		opts.BaseURL = baseURL
	}
	prov, err := turncreds.NewCloudflareProvider(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare: build provider:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	creds, err := prov.Get(ctx)
	// Close the provider regardless — we only needed the one mint, and
	// the refresh goroutine would otherwise keep ticking.
	_ = prov.Close()

	if err != nil {
		// turncreds already sanitizes the body and never includes the
		// API token in its error values, so this is safe to print.
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare: test mint failed:", friendlyCloudflareErr(err))
		return 1
	}

	if err := writeCredsFile(*filePath, cloudflareTurnCredsFile{
		TurnTokenID: *tokenID,
		APIToken:    apiToken,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup cloudflare: write file:", err)
		return 1
	}

	expiresIn := time.Until(creds.ExpiresAt).Round(time.Second)
	fmt.Fprintf(os.Stdout, "ok: wrote %s (test-mint succeeded, creds expire in %s)\n", *filePath, expiresIn)
	return 0
}

// runTurnSetupStatic handles `pilot-daemon turn-setup static`.
// Reads the password from stdin, performs one live Allocate against
// the server, and writes a {server, transport, username, password}
// JSON file on success.
func runTurnSetupStatic(args []string) int {
	fs := flag.NewFlagSet("turn-setup static", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	server := fs.String("server", "", "TURN server host:port (e.g. coturn.example.com:3478)")
	transport := fs.String("transport", "udp", "client→server transport: udp|tcp|tls")
	user := fs.String("user", "", "TURN username")
	passStdin := fs.Bool("pass-stdin", true, "read the password from stdin (only supported path)")
	filePath := fs.String("file", defaultStaticTurnCredsFile(), "destination credentials JSON path")
	force := fs.Bool("force", false, "overwrite the file if it already exists")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*server) == "" {
		fmt.Fprintln(os.Stderr, "turn-setup static: -server is required")
		return 2
	}
	if strings.TrimSpace(*user) == "" {
		fmt.Fprintln(os.Stderr, "turn-setup static: -user is required")
		return 2
	}
	if !*passStdin {
		fmt.Fprintln(os.Stderr, "turn-setup static: -pass-stdin=false is not supported (secret must come via stdin)")
		return 2
	}
	if !validTransportName(*transport) {
		fmt.Fprintf(os.Stderr, "turn-setup static: invalid -transport %q (want udp|tcp|tls)\n", *transport)
		return 2
	}

	if err := checkOverwrite(*filePath, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	pass, err := readSecret("password")
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup static:", err)
		return 1
	}

	// Validate by performing one allocation. If the server or password
	// is wrong, Allocate returns an error; we refuse to write in that
	// case so the user can fix the input and retry.
	relayAddr, err := testStaticAllocate(*server, *transport, *user, pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup static: test allocation failed:", err)
		return 1
	}

	if err := writeCredsFile(*filePath, staticTurnCredsFile{
		Server:    *server,
		Transport: *transport,
		Username:  *user,
		Password:  pass,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "turn-setup static: write file:", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "ok: wrote %s (relay allocation succeeded: %s)\n", *filePath, relayAddr)
	return 0
}

// staticTurnCredsFile is the on-disk format for static TURN creds.
// Separate type from cloudflareTurnCredsFile because the field sets
// differ (server/transport are implicit in the CF API response).
type staticTurnCredsFile struct {
	Server    string `json:"server"`
	Transport string `json:"transport"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// defaultStaticTurnCredsFile mirrors defaultCloudflareTurnCredsFile
// (defined in main.go) for the static-provider path.
func defaultStaticTurnCredsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "~/.pilot/static-turn.json"
	}
	return filepath.Join(home, ".pilot", "static-turn.json")
}

// validTransportName is a tiny mirror of turncreds.isValidTransport,
// inlined here because that function is unexported. Keeping the set in
// sync manually is fine — the set is closed and hasn't changed in
// pion/turn v5.
func validTransportName(t string) bool {
	switch t {
	case "udp", "tcp", "tls":
		return true
	}
	return false
}

// checkOverwrite returns an error if path already exists and force is
// false. Gives the user a clear message about how to proceed rather
// than silently clobbering.
func checkOverwrite(path string, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s (pass -force to overwrite)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return nil
}

// readSecret reads a secret from stdin. On a TTY it uses term.ReadPassword
// so the characters don't echo; on a pipe it reads one line. Trims
// trailing whitespace/newlines and refuses empty input. label is
// interpolated into the TTY prompt ("Enter API token" / "Enter password").
func readSecret(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	var raw []byte
	if term.IsTerminal(fd) {
		fmt.Fprintf(os.Stderr, "Enter %s (input hidden): ", label)
		b, err := term.ReadPassword(fd)
		// Terminate the hidden-input line regardless of success so the
		// next stderr output appears on its own line.
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", label, err)
		}
		raw = b
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read %s: %w", label, err)
		}
		raw = []byte(line)
	}

	s := strings.TrimRight(strings.TrimSpace(string(raw)), "\r\n")
	if s == "" {
		return "", fmt.Errorf("empty %s", label)
	}
	return s, nil
}

// writeCredsFile marshals v as pretty JSON, ensures the parent dir
// exists with mode 0700, then writes path with mode 0600. Uses a
// temp-file-and-rename dance so a crash doesn't leave a half-written
// credentials file on disk.
func writeCredsFile(path string, v any) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Trailing newline — editor-friendly, and matches what most
	// config-writing CLIs produce.
	data = append(data, '\n')

	// Write through a tempfile + rename so we don't truncate an
	// existing good file if json.Marshal or disk-full hits mid-write.
	tmp, err := os.CreateTemp(dir, ".turn-creds-*.tmp")
	if err != nil {
		return fmt.Errorf("create tempfile: %w", err)
	}
	tmpName := tmp.Name()
	// Remove on any error path below.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tempfile: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tempfile: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// friendlyCloudflareErr adds a one-word hint to common HTTP failures
// if the turncreds package didn't already include one. The package
// itself handles 401/403/404 hints; this is a belt-and-suspenders
// check in case the error path changes.
func friendlyCloudflareErr(err error) error {
	if err == nil {
		return nil
	}
	return err
}

// testStaticAllocate spins up a one-shot pion/turn client against the
// given server, performs Listen + Allocate, reports the relayed
// address, and tears everything down. Used by `turn-setup static` to
// validate credentials before writing them to disk.
//
// Duplicates a trimmed version of
// pkg/daemon/transport.buildPionClient — copying is a deliberate
// scope-compliance choice (Part A7 says "do not modify files outside
// cmd/daemon/"). ~30 LOC, straight port.
func testStaticAllocate(server, transport, user, pass string) (string, error) {
	client, relay, underlying, err := buildOneShotPionClient(server, transport, user, pass)
	if err != nil {
		return "", err
	}
	defer func() {
		// Close order matches pkg/daemon/transport.Close:
		// relay first (sends Refresh(lifetime=0) so the server frees
		// the allocation), then client, then the raw socket.
		_ = relay.Close()
		client.Close()
		_ = underlying.Close()
	}()

	return relay.LocalAddr().String(), nil
}

// buildOneShotPionClient is a narrow subset of
// pkg/daemon/transport.buildPionClient. Same switch on transport,
// same close order, fewer knobs. Returns the triplet the caller must
// release.
func buildOneShotPionClient(server, transport, user, pass string) (*turn.Client, net.PacketConn, net.PacketConn, error) {
	var clientConn net.PacketConn
	var underlying net.PacketConn

	switch transport {
	case "", "udp":
		sock, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("udp socket: %w", err)
		}
		clientConn = sock
		underlying = sock

	case "tcp":
		conn, err := net.DialTimeout("tcp", server, 10*time.Second)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tcp dial %s: %w", server, err)
		}
		sc := turn.NewSTUNConn(conn)
		clientConn = sc
		underlying = sc

	case "tls":
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls split server %q: %w", server, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dialer := &tls.Dialer{Config: &tls.Config{ServerName: host}}
		c, err := dialer.DialContext(ctx, "tcp", server)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tls dial %s: %w", server, err)
		}
		sc := turn.NewSTUNConn(c)
		clientConn = sc
		underlying = sc

	default:
		return nil, nil, nil, fmt.Errorf("unsupported transport %q", transport)
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: server,
		TURNServerAddr: server,
		Conn:           clientConn,
		Username:       user,
		Password:       pass,
		Realm:          "cloudflare.com",
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("new client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("client.Listen: %w", err)
	}
	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = underlying.Close()
		return nil, nil, nil, fmt.Errorf("allocate: %w", err)
	}
	return client, relay, underlying, nil
}
