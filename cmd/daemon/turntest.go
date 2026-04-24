package main

// turntest implements the `pilot-daemon turn-test` subcommand. It
// reads the credentials file the daemon would use, performs one
// mint + allocate + close cycle, and reports each step on its own
// stdout line. Exit 0 on full PASS, 1 on any failure, 2 on missing
// configuration.
//
// Step-by-step output lets a user running this under a shell Ctrl-C
// see how far the test got, which is exactly the information they
// need to file a useful bug report. We flush after every Fprintln by
// never buffering — os.Stdout is line-buffered on a terminal and
// unbuffered on a pipe, and we rely on Go's os.File default.

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pion/turn/v5"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/turncreds"
)

// turnTestUsage documents the single subcommand's flags.
const turnTestUsage = `usage: pilot-daemon turn-test [flags]

Performs a live TURN mint + allocate + close cycle and prints each
step. Intended as a post-setup smoke test. Reads the same credentials
files the daemon uses at startup.

flags:
  -provider <name>     "cloudflare" or "static" (default: auto-detect)
  -file <path>         credentials file (default: depends on provider)
  -transport <name>    udp|tcp|tls (default: taken from file, else udp)
  -ttl <duration>      Cloudflare test-mint TTL (default: 1h; static ignores)
`

// runTurnTest is the entry point for the `turn-test` subcommand.
func runTurnTest(args []string) int {
	fs := flag.NewFlagSet("turn-test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	provider := fs.String("provider", "", `credential provider ("" = auto-detect; "cloudflare" or "static")`)
	filePath := fs.String("file", "", "credentials file path ('' = default for chosen provider)")
	transport := fs.String("transport", "", `client→server transport: udp|tcp|tls ('' = take from file, else udp)`)
	ttl := fs.Duration("ttl", 1*time.Hour, "Cloudflare test-mint TTL (static ignores)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Resolve provider kind and file path, filling defaults / auto-
	// detecting as needed.
	kind, path, err := resolveProviderAndFile(*provider, *filePath)
	if err != nil {
		fmt.Fprintln(os.Stdout, "turn-test:", err)
		return 2
	}

	// Warn (but don't abort) if the creds file has overly permissive
	// mode. Other users on the box could otherwise read the secret.
	warnIfWorldReadable(path)

	switch kind {
	case "cloudflare":
		return runTurnTestCloudflare(path, *transport, *ttl)
	case "static":
		return runTurnTestStatic(path, *transport)
	default:
		fmt.Fprintf(os.Stdout, "turn-test: unknown provider %q\n", kind)
		return 2
	}
}

// resolveProviderAndFile fills in defaults. If both flags are empty,
// probes the two default paths and prefers cloudflare. Returns
// (kind, path, err). Err is non-nil only when neither file exists and
// no explicit provider was given.
func resolveProviderAndFile(provider, file string) (string, string, error) {
	switch provider {
	case "cloudflare":
		if file == "" {
			file = defaultCloudflareTurnCredsFile()
		}
		return "cloudflare", file, nil
	case "static":
		if file == "" {
			file = defaultStaticTurnCredsFile()
		}
		return "static", file, nil
	case "":
		// Auto-detect.
		cfPath := defaultCloudflareTurnCredsFile()
		stPath := defaultStaticTurnCredsFile()
		if file != "" {
			// Can't infer kind from a non-default path; ask the user.
			return "", file, fmt.Errorf("-file given without -provider; pass -provider=cloudflare or -provider=static")
		}
		if _, err := os.Stat(cfPath); err == nil {
			return "cloudflare", cfPath, nil
		}
		if _, err := os.Stat(stPath); err == nil {
			return "static", stPath, nil
		}
		return "", "", fmt.Errorf("no TURN config found at %s or %s; run `pilot-daemon turn-setup ...` first", cfPath, stPath)
	default:
		return "", "", fmt.Errorf("unknown -provider %q (want cloudflare or static)", provider)
	}
}

// warnIfWorldReadable prints a one-line warning to stderr (not the
// step stream) if the creds file is group- or world-readable. We do
// NOT refuse to proceed — the user may knowingly accept the risk (and
// on some shared-VM setups 0600 is impossible). Logging the issue is
// enough.
func warnIfWorldReadable(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "turn-test: warning: %s mode %04o is group/world-readable; consider `chmod 600`\n", path, perm)
	}
}

// runTurnTestCloudflare is the cloudflare path. Mints via the real
// API (or httptest.Server in tests — turncreds honors BaseURL via
// options, but the test file writes a real-looking config that points
// at the mock only after we rig the provider; see the test plan).
func runTurnTestCloudflare(path, transportOverride string, ttl time.Duration) int {
	stepStart("loading %s", path)
	data, err := os.ReadFile(path)
	if err != nil {
		stepFail(err)
		return end(false)
	}
	var cf cloudflareTurnCredsFile
	if err := json.Unmarshal(data, &cf); err != nil {
		stepFail(fmt.Errorf("parse %s: %w", path, err))
		return end(false)
	}
	if cf.TurnTokenID == "" || cf.APIToken == "" {
		stepFail(fmt.Errorf("%s: missing turn_token_id or api_token", path))
		return end(false)
	}
	stepOK("")

	transport := transportOverride
	if transport == "" {
		transport = "udp"
	}
	if !validTransportName(transport) {
		stepStart("validating transport")
		stepFail(fmt.Errorf("invalid transport %q (want udp|tcp|tls)", transport))
		return end(false)
	}

	opts := turncreds.CloudflareOptions{
		TokenID:   cf.TurnTokenID,
		APIToken:  cf.APIToken,
		TTL:       ttl,
		Transport: transport,
	}
	// Test-only hook: if a base URL is set via env (see tests), honor
	// it. Production users should never set this.
	if baseURL := os.Getenv("PILOT_CLOUDFLARE_TURN_BASE_URL"); baseURL != "" {
		opts.BaseURL = baseURL
	}

	stepStart("minting Cloudflare credentials")
	prov, err := turncreds.NewCloudflareProvider(opts)
	if err != nil {
		stepFail(err)
		return end(false)
	}
	defer prov.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	creds, err := prov.Get(ctx)
	if err != nil {
		stepFail(friendlyCloudflareErr(err))
		return end(false)
	}
	stepOK(fmt.Sprintf("ttl=%s, expires %s", ttl, creds.ExpiresAt.UTC().Format(time.RFC3339)))

	return runAllocateStep(creds, true)
}

// runTurnTestStatic is the static path. Same step sequence as the
// cloudflare path, but the "mint" step is trivial (static providers
// have nothing to mint).
func runTurnTestStatic(path, transportOverride string) int {
	stepStart("loading %s", path)
	data, err := os.ReadFile(path)
	if err != nil {
		stepFail(err)
		return end(false)
	}
	var st staticTurnCredsFile
	if err := json.Unmarshal(data, &st); err != nil {
		stepFail(fmt.Errorf("parse %s: %w", path, err))
		return end(false)
	}
	if st.Server == "" || st.Username == "" || st.Password == "" {
		stepFail(fmt.Errorf("%s: missing server/username/password", path))
		return end(false)
	}
	transport := transportOverride
	if transport == "" {
		transport = st.Transport
	}
	if transport == "" {
		transport = "udp"
	}
	if !validTransportName(transport) {
		stepFail(fmt.Errorf("invalid transport %q (want udp|tcp|tls)", transport))
		return end(false)
	}
	stepOK("")

	stepStart("loading static credentials")
	prov, err := turncreds.NewStaticProvider(st.Server, transport, st.Username, st.Password)
	if err != nil {
		stepFail(err)
		return end(false)
	}
	defer prov.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	creds, err := prov.Get(ctx)
	if err != nil {
		stepFail(err)
		return end(false)
	}
	stepOK("")

	return runAllocateStep(creds, false)
}

// runAllocateStep runs the connect + allocate + close step sequence
// that both cloudflare and static paths share. Returns the process
// exit code.
func runAllocateStep(creds *turncreds.Credentials, _ bool) int {
	stepStart("connecting to %s (%s)", creds.ServerAddr, creds.Transport)
	client, relay, underlying, err := buildOneShotPionClient(
		creds.ServerAddr, creds.Transport, creds.Username, creds.Password,
	)
	if err != nil {
		// buildOneShotPionClient already wraps client.Listen /
		// allocate errors — strip the first '/' so we get either
		// "connecting" or "allocating" hint depending on the wrapped
		// error. Easier to just emit the raw message.
		if strings.Contains(err.Error(), "allocate:") {
			// connect actually succeeded; the Listen succeeded too.
			stepOK("")
			stepStart("allocating relay")
			stepFail(err)
			return end(false)
		}
		if strings.Contains(err.Error(), "client.Listen:") {
			stepFail(err)
			return end(false)
		}
		stepFail(err)
		return end(false)
	}
	stepOK("")

	stepStart("allocating relay")
	// The pion client already called Allocate inside
	// buildOneShotPionClient; if we got here, allocation succeeded.
	relayed := relay.LocalAddr().String()
	stepOK("")

	// Human-readable summary line between the allocate and close steps.
	fmt.Fprintf(os.Stdout, "turn-test: relayed address: %s\n", relayed)

	stepStart("closing")
	closeErr := closeOneShotPionClient(client, relay, underlying)
	if closeErr != nil {
		stepFail(closeErr)
		return end(false)
	}
	stepOK("")

	return end(true)
}

// closeOneShotPionClient tears down the triplet in the documented
// order. Pion close functions swallow individual errors; only the
// relay's Refresh(lifetime=0) send is interesting, and even that is
// best-effort. "use of closed network connection" on the underlying
// socket after client.Close is expected and silently ignored.
func closeOneShotPionClient(client *turn.Client, relay net.PacketConn, underlying net.PacketConn) error {
	var firstErr error
	if err := relay.Close(); err != nil && firstErr == nil && !isClosedErr(err) {
		firstErr = err
	}
	client.Close()
	if err := underlying.Close(); err != nil && firstErr == nil && !isClosedErr(err) {
		firstErr = err
	}
	return firstErr
}

// isClosedErr reports whether err is the net.ErrClosed sentinel
// (directly or wrapped). Used to ignore expected
// "use of closed network connection" errors during teardown.
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// stepStart prints "turn-test: <msg>..." with no trailing newline so
// the follow-up stepOK/stepFail lands on the same line. Follows the
// plan's output format exactly.
func stepStart(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "turn-test: "+format+"... ", args...)
}

// stepOK prints "ok" (with an optional parenthetical suffix) and
// terminates the line.
func stepOK(suffix string) {
	if suffix == "" {
		fmt.Fprintln(os.Stdout, "ok")
		return
	}
	fmt.Fprintf(os.Stdout, "ok (%s)\n", suffix)
}

// stepFail prints "FAIL: <err>" and terminates the line.
func stepFail(err error) {
	fmt.Fprintf(os.Stdout, "FAIL: %s\n", err)
}

// end prints the terminal PASS/FAIL marker and returns the exit code.
func end(pass bool) int {
	if pass {
		fmt.Fprintln(os.Stdout, "turn-test: PASS")
		return 0
	}
	fmt.Fprintln(os.Stdout, "turn-test: FAIL")
	return 1
}
