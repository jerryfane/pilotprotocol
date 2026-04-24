package main

// Tests for `pilot-daemon turn-setup cloudflare|static`.
//
// Strategy:
//   - Cloudflare: a httptest.Server mocks the Cloudflare mint
//     endpoint. We override the turncreds Cloudflare provider's
//     BaseURL via PILOT_CLOUDFLARE_TURN_BASE_URL — but wait, that's
//     only honored in turntest.go for the test path. For turnsetup
//     we can't inject via env because runTurnSetupCloudflare calls
//     NewCloudflareProvider directly. Rather than plumb an env var
//     through production code, we drive runTurnSetupCloudflare by
//     setting an env var it knows about (PILOT_CLOUDFLARE_TURN_BASE_URL)
//     — the prod path ignores unknown env vars, so this is safe.
//
//   - Static: a pion/turn server runs in-process on an ephemeral UDP
//     port. Tests register a credMap and drive the subcommand against
//     it.
//
// stdin redirection follows the pattern documented in the task
// description: swap os.Stdin with a *os.File from os.Pipe, write the
// secret bytes to the writer, close it, restore Stdin in a defer.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// withStdin replaces os.Stdin with a pipe prepared with the given
// bytes. Returns a restore function the caller should defer. Empty
// input is allowed (produces an immediate EOF on ReadString).
func withStdin(t *testing.T, input string) func() {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	if input != "" {
		if _, err := io.WriteString(w, input); err != nil {
			t.Fatalf("write stdin: %v", err)
		}
	}
	// Close the writer so bufio's ReadString sees EOF on the empty
	// case and a completed line in the happy case.
	_ = w.Close()
	return func() {
		os.Stdin = old
		_ = r.Close()
	}
}

// withStdoutStderr captures os.Stdout and os.Stderr into bytes
// buffers for assertion. Returns (restore, stdoutGetter,
// stderrGetter).
func withStdoutStderr(t *testing.T) (func() (string, string), func()) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = wOut
	os.Stderr = wErr

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() { b, _ := io.ReadAll(rOut); outCh <- string(b) }()
	go func() { b, _ := io.ReadAll(rErr); errCh <- string(b) }()

	restore := func() {
		// Close the writers so the goroutines unblock.
		_ = wOut.Close()
		_ = wErr.Close()
		os.Stdout = oldOut
		os.Stderr = oldErr
	}
	getAll := func() (string, string) {
		return <-outCh, <-errCh
	}
	return getAll, restore
}

// mockCloudflareServer returns an httptest.Server that serves the
// Cloudflare Realtime TURN mint endpoint. status controls the
// response code; when 200, returns a well-formed iceServers payload.
func mockCloudflareServer(t *testing.T, status int, calls *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/turn/keys/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
		resp := map[string]any{
			"iceServers": []map[string]any{
				{
					"urls":       []string{"turn:turn.example.com:3478?transport=udp"},
					"username":   "u",
					"credential": "p",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

// TestTurnSetupCloudflare_HappyPath verifies that a valid token-id +
// API token round-trip writes a 0600 file with the expected JSON
// contents and returns exit code 0.
func TestTurnSetupCloudflare_HappyPath(t *testing.T) {
	var calls int32
	srv := mockCloudflareServer(t, http.StatusOK, &calls)
	defer srv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", srv.URL)

	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-turn.json")

	restoreStdin := withStdin(t, "my-api-token\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupCloudflare([]string{
		"-token-id=test-key-id",
		"-file=" + path,
	})
	restoreOut()
	stdout, stderr := getOutput()

	if code != 0 {
		t.Fatalf("exit=%d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatalf("expected mock Cloudflare to be called")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}

	var cf cloudflareTurnCredsFile
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if err := json.Unmarshal(data, &cf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cf.TurnTokenID != "test-key-id" {
		t.Fatalf("TurnTokenID=%q, want test-key-id", cf.TurnTokenID)
	}
	if cf.APIToken != "my-api-token" {
		t.Fatalf("APIToken mismatch")
	}
	if !strings.Contains(stdout, "ok: wrote") {
		t.Fatalf("stdout missing ok: prefix: %q", stdout)
	}
}

// Wire the test-mode env var into the cloudflare setup path. Because
// runTurnSetupCloudflare calls NewCloudflareProvider directly, we
// need to honor the same env var the turn-test path uses. Add a tiny
// integration hook at call time rather than modifying prod; the test
// exercises the same observable behavior because NewCloudflareProvider
// accepts a BaseURL.
//
// Implementation: inject via a wrapping call. Simpler: add BaseURL
// honoring to runTurnSetupCloudflare behind the same env var. Done in
// turnsetup.go via a small lookup before NewCloudflareProvider.

// TestTurnSetupCloudflare_EmptyToken: piped stdin empty -> exit != 0,
// no file written.
func TestTurnSetupCloudflare_EmptyToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-turn.json")

	restoreStdin := withStdin(t, "")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupCloudflare([]string{
		"-token-id=test-key-id",
		"-file=" + path,
	})
	restoreOut()
	_, stderr := getOutput()

	if code == 0 {
		t.Fatalf("exit=0, want non-zero")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file was written on failure: %v", err)
	}
	if !strings.Contains(stderr, "empty") {
		t.Fatalf("stderr should mention empty input: %q", stderr)
	}
}

// TestTurnSetupCloudflare_HttpError: mock returns 401 -> non-zero,
// no file, stderr mentions api_token hint.
func TestTurnSetupCloudflare_HttpError(t *testing.T) {
	var calls int32
	srv := mockCloudflareServer(t, http.StatusUnauthorized, &calls)
	defer srv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", srv.URL)

	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-turn.json")

	restoreStdin := withStdin(t, "bad-token\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupCloudflare([]string{
		"-token-id=test-key-id",
		"-file=" + path,
	})
	restoreOut()
	_, stderr := getOutput()

	if code == 0 {
		t.Fatalf("exit=0 with 401 response, want non-zero")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file written despite 401: %v", err)
	}
	if !strings.Contains(stderr, "api_token") {
		t.Fatalf("stderr should hint at api_token: %q", stderr)
	}
}

// TestTurnSetupCloudflare_FileExists: pre-create file without
// -force -> exit != 0 and file contents preserved.
func TestTurnSetupCloudflare_FileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-turn.json")
	original := []byte(`{"preserve":"me"}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("prewrite: %v", err)
	}

	restoreStdin := withStdin(t, "token\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupCloudflare([]string{
		"-token-id=test-key-id",
		"-file=" + path,
	})
	restoreOut()
	_, _ = getOutput()

	if code == 0 {
		t.Fatalf("exit=0, want non-zero when file exists without -force")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("file clobbered: %q", got)
	}
}

// TestTurnSetupCloudflare_Force overwrites existing file when -force
// passed, with a healthy mint response.
func TestTurnSetupCloudflare_Force(t *testing.T) {
	var calls int32
	srv := mockCloudflareServer(t, http.StatusOK, &calls)
	defer srv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", srv.URL)

	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare-turn.json")
	if err := os.WriteFile(path, []byte(`{"old":"data"}`), 0o600); err != nil {
		t.Fatalf("prewrite: %v", err)
	}

	restoreStdin := withStdin(t, "new-token\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupCloudflare([]string{
		"-token-id=new-key-id",
		"-file=" + path,
		"-force",
	})
	restoreOut()
	_, _ = getOutput()

	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	var cf cloudflareTurnCredsFile
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cf.TurnTokenID != "new-key-id" || cf.APIToken != "new-token" {
		t.Fatalf("file not overwritten: %+v", cf)
	}
}

// --- static subcommand tests -----------------------------------------

// staticTestServer is a small wrapper around turn.NewServer tuned for
// in-process allocation tests. Accepts any username present in
// credMap. Returns "host:port" and a cleanup func.
func staticTestServer(t *testing.T, credMap map[string]string) (string, func()) {
	t.Helper()
	const realm = "pion.test"
	authHandler := func(ra *turn.RequestAttributes) (string, []byte, bool) {
		pw, ok := credMap[ra.Username]
		if !ok {
			return "", nil, false
		}
		return ra.Username, turn.GenerateAuthKey(ra.Username, realm, pw), true
	}
	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   authHandler,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
	})
	if err != nil {
		_ = udpListener.Close()
		t.Fatalf("turn.NewServer: %v", err)
	}
	addr := udpListener.LocalAddr().(*net.UDPAddr).String()
	return addr, func() { _ = server.Close() }
}

// TestTurnSetupStatic_HappyPath: spin up pion server, run the
// subcommand with valid creds, check file.
func TestTurnSetupStatic_HappyPath(t *testing.T) {
	srvAddr, cleanup := staticTestServer(t, map[string]string{"alice": "secret"})
	defer cleanup()

	dir := t.TempDir()
	path := filepath.Join(dir, "static-turn.json")

	restoreStdin := withStdin(t, "secret\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupStatic([]string{
		"-server=" + srvAddr,
		"-user=alice",
		"-file=" + path,
	})
	restoreOut()
	stdout, stderr := getOutput()

	if code != 0 {
		t.Fatalf("exit=%d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode=%04o, want 0600", perm)
	}
	var st staticTurnCredsFile
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if st.Server != srvAddr || st.Username != "alice" || st.Password != "secret" || st.Transport != "udp" {
		t.Fatalf("file contents wrong: %+v", st)
	}
	if !strings.Contains(stdout, "relay allocation succeeded") {
		t.Fatalf("stdout missing success line: %q", stdout)
	}
}

// TestTurnSetupStatic_BadCreds: pion rejects wrong password ->
// non-zero, no file.
func TestTurnSetupStatic_BadCreds(t *testing.T) {
	srvAddr, cleanup := staticTestServer(t, map[string]string{"alice": "right"})
	defer cleanup()

	dir := t.TempDir()
	path := filepath.Join(dir, "static-turn.json")

	restoreStdin := withStdin(t, "wrong\n")
	defer restoreStdin()
	getOutput, restoreOut := withStdoutStderr(t)

	code := runTurnSetupStatic([]string{
		"-server=" + srvAddr,
		"-user=alice",
		"-file=" + path,
	})
	restoreOut()
	_, stderr := getOutput()

	if code == 0 {
		t.Fatalf("exit=0, want non-zero on auth failure")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file was written despite failure")
	}
	if !strings.Contains(stderr, "test allocation failed") {
		t.Fatalf("stderr missing failure marker: %q", stderr)
	}
}

// TestRunTurnSetup_UsageNoArgs: no subcommand prints usage and exits 2.
func TestRunTurnSetup_UsageNoArgs(t *testing.T) {
	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnSetup(nil)
	restoreOut()
	_, stderr := getOutput()

	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(stderr, "usage: pilot-daemon turn-setup") {
		t.Fatalf("stderr missing usage: %q", stderr)
	}
}
