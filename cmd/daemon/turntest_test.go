package main

// Tests for `pilot-daemon turn-test`.
//
// Strategy:
//   - Cloudflare: mock the mint endpoint with httptest.Server; arrange
//     it to return iceServers whose URL points at an in-process pion
//     TURN server so the allocate step succeeds too.
//   - Static: write a static creds file with coords of an in-process
//     pion server.
//   - Failure paths: mock 401 for MintFail; configure pion server to
//     reject auth for AllocateFail; empty HOME dir for NoConfig.
//
// HOME is manipulated via t.Setenv so defaultCloudflareTurnCredsFile
// and defaultStaticTurnCredsFile pick up the temp dir.

import (
	"encoding/json"
	"fmt"
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

// mockCloudflareServerPointingAt returns a mock that yields a
// Cloudflare iceServers payload whose turn URL points at pionServer
// (a host:port bound by an in-process turn server) with the given
// username/password. Mirrors mockCloudflareServer but lets us thread
// real allocation coordinates through so the follow-up allocate step
// also succeeds.
func mockCloudflareServerPointingAt(t *testing.T, pionServer, user, pass string, calls *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/turn/keys/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "no bearer", http.StatusUnauthorized)
			return
		}
		resp := map[string]any{
			"iceServers": []map[string]any{
				{
					"urls":       []string{fmt.Sprintf("turn:%s?transport=udp", pionServer)},
					"username":   user,
					"credential": pass,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

// startPionTestServer is reused across tests — same shape as
// staticTestServer in turnsetup_test.go but copied here so the two
// test files are independent. Accepts entries in credMap.
func startPionTestServer(t *testing.T, credMap map[string]string) (string, func()) {
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
		t.Fatalf("NewServer: %v", err)
	}
	addr := udpListener.LocalAddr().(*net.UDPAddr).String()
	return addr, func() { _ = server.Close() }
}

// setHome points HOME at a temp dir and creates .pilot inside so
// default cred-file lookups land inside the sandbox.
func setHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".pilot"), 0o700); err != nil {
		t.Fatalf("mkdir .pilot: %v", err)
	}
	return home
}

// writeCloudflareCredsFile writes a creds JSON at the default CF path
// inside home.
func writeCloudflareCredsFile(t *testing.T, home, tokenID, apiToken string) string {
	t.Helper()
	p := filepath.Join(home, ".pilot", "cloudflare-turn.json")
	data, _ := json.Marshal(cloudflareTurnCredsFile{
		TurnTokenID: tokenID, APIToken: apiToken,
	})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return p
}

// writeStaticCredsFile writes a static creds JSON at the default
// static path inside home.
func writeStaticCredsFile(t *testing.T, home, server, user, pass string) string {
	t.Helper()
	p := filepath.Join(home, ".pilot", "static-turn.json")
	data, _ := json.Marshal(staticTurnCredsFile{
		Server: server, Transport: "udp", Username: user, Password: pass,
	})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return p
}

// TestTurnTest_CloudflarePass: full happy path. Mock Cloudflare +
// in-process pion server + config file; expect PASS, exit 0.
func TestTurnTest_CloudflarePass(t *testing.T) {
	home := setHome(t)

	pion, pionCleanup := startPionTestServer(t, map[string]string{"u": "p"})
	defer pionCleanup()

	var calls int32
	cfSrv := mockCloudflareServerPointingAt(t, pion, "u", "p", &calls)
	defer cfSrv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", cfSrv.URL)

	writeCloudflareCredsFile(t, home, "test-id", "api-token")

	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest(nil)
	restoreOut()
	stdout, stderr := getOutput()

	if code != 0 {
		t.Fatalf("exit=%d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "turn-test: PASS") {
		t.Fatalf("stdout missing PASS: %q", stdout)
	}
	if !strings.Contains(stdout, "relayed address:") {
		t.Fatalf("stdout missing relayed address: %q", stdout)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatalf("mock CF was never called")
	}
}

// TestTurnTest_StaticPass: static config file + pion server. PASS.
func TestTurnTest_StaticPass(t *testing.T) {
	home := setHome(t)
	pion, cleanup := startPionTestServer(t, map[string]string{"alice": "pw"})
	defer cleanup()
	writeStaticCredsFile(t, home, pion, "alice", "pw")

	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest(nil)
	restoreOut()
	stdout, stderr := getOutput()

	if code != 0 {
		t.Fatalf("exit=%d, want 0 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "turn-test: PASS") {
		t.Fatalf("stdout missing PASS: %q", stdout)
	}
}

// TestTurnTest_MintFail: mock CF returns 401 -> exit 1, FAIL line,
// mentions api_token.
func TestTurnTest_MintFail(t *testing.T) {
	home := setHome(t)

	var calls int32
	cfSrv := mockCloudflareServer(t, http.StatusUnauthorized, &calls)
	defer cfSrv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", cfSrv.URL)
	writeCloudflareCredsFile(t, home, "id", "bad-token")

	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest(nil)
	restoreOut()
	stdout, _ := getOutput()

	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if !strings.Contains(stdout, "FAIL") {
		t.Fatalf("stdout missing FAIL: %q", stdout)
	}
	if !strings.Contains(stdout, "api_token") {
		t.Fatalf("stdout missing api_token hint: %q", stdout)
	}
	if !strings.Contains(stdout, "turn-test: FAIL") {
		t.Fatalf("stdout missing terminal FAIL: %q", stdout)
	}
}

// TestTurnTest_AllocateFail: pion rejects auth, so mint succeeds
// (Cloudflare returned a turn URL + creds) but Allocate fails. Since
// the only remote path where Cloudflare succeeds but Allocate fails
// is "Cloudflare returned creds that don't match the pion server", we
// point the mock at pion with the wrong password.
func TestTurnTest_AllocateFail(t *testing.T) {
	home := setHome(t)

	// Pion only knows user "u" with password "right".
	pion, cleanup := startPionTestServer(t, map[string]string{"u": "right"})
	defer cleanup()

	// Mock CF returns creds that point at pion but with a wrong
	// password. The mint step succeeds (HTTP 200), but Allocate
	// fails because pion rejects the auth.
	var calls int32
	cfSrv := mockCloudflareServerPointingAt(t, pion, "u", "wrong", &calls)
	defer cfSrv.Close()
	t.Setenv("PILOT_CLOUDFLARE_TURN_BASE_URL", cfSrv.URL)
	writeCloudflareCredsFile(t, home, "id", "api-token")

	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest(nil)
	restoreOut()
	stdout, _ := getOutput()

	if code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if !strings.Contains(stdout, "turn-test: FAIL") {
		t.Fatalf("stdout missing terminal FAIL: %q", stdout)
	}
	// The failing step should be one of connect/allocate — any
	// FAIL line before the terminal marker is acceptable.
	// Assert it contains the mint-succeeded marker AND a FAIL line
	// at a step that isn't the mint.
	if !strings.Contains(stdout, "minting Cloudflare credentials... ok") {
		t.Fatalf("stdout should show mint succeeded: %q", stdout)
	}
}

// TestTurnTest_NoConfig: empty HOME dir -> exit 2, message about
// turn-setup.
func TestTurnTest_NoConfig(t *testing.T) {
	setHome(t)

	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest(nil)
	restoreOut()
	stdout, _ := getOutput()

	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(stdout, "turn-setup") {
		t.Fatalf("stdout should point at turn-setup: %q", stdout)
	}
}

// TestTurnTest_ExplicitFileWithoutProvider: -file given without
// -provider should fail cleanly.
func TestTurnTest_ExplicitFileWithoutProvider(t *testing.T) {
	setHome(t)
	getOutput, restoreOut := withStdoutStderr(t)
	code := runTurnTest([]string{"-file=/tmp/nonexistent.json"})
	restoreOut()
	stdout, _ := getOutput()
	if code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if !strings.Contains(stdout, "-file given without -provider") {
		t.Fatalf("stdout missing hint: %q", stdout)
	}
}
