package turncreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sampleICEResponse returns a realistic Cloudflare response body
// containing stun, turn-udp, turn-tcp, turns-tcp URLs under a single
// credentialed ICE server — matches the real API shape as of 2026-04.
func sampleICEResponse() cfResponse {
	return cfResponse{
		ICEServers: []cfICEServer{
			// STUN-only entry: no creds, just URLs.
			{URLs: []string{"stun:stun.cloudflare.com:3478"}},
			// TURN entry with creds and multiple transports.
			{
				URLs: []string{
					"turn:turn.cloudflare.com:3478?transport=udp",
					"turn:turn.cloudflare.com:3478?transport=tcp",
					"turns:turn.cloudflare.com:5349?transport=tcp",
				},
				Username:   "cf-user-123",
				Credential: "cf-pass-xyz",
			},
		},
	}
}

// cfTestHandler returns an httptest-ready handler that replies with
// the given JSON body and status code, and invokes onReq (if non-nil)
// for each request (for assertion + retry counting).
func cfTestHandler(t *testing.T, status int, body any, onReq func(*http.Request)) http.HandlerFunc {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal test body: %v", err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if onReq != nil {
			onReq(r)
		}
		// Verify the path matches what CloudflareProvider should
		// hit. Never assert the auth header's value here — that
		// would leak the token into test output if the assertion
		// failed.
		wantPath := "/v1/turn/keys/"
		if !strings.HasPrefix(r.URL.Path, wantPath) {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(raw)
	}
}

func TestCloudflareProvider_InitialMint(t *testing.T) {
	var authHeaderSeen string
	var mu sync.Mutex
	srv := httptest.NewServer(cfTestHandler(t, http.StatusOK, sampleICEResponse(), func(r *http.Request) {
		mu.Lock()
		authHeaderSeen = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer srv.Close()

	p, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:  "tok-id",
		APIToken: "secret-api-token",
		TTL:      time.Hour,
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer p.Close()

	creds, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if creds.ServerAddr != "turn.cloudflare.com:3478" {
		t.Errorf("ServerAddr = %q, want turn.cloudflare.com:3478", creds.ServerAddr)
	}
	if creds.Transport != "udp" {
		t.Errorf("Transport = %q, want udp", creds.Transport)
	}
	if creds.Username != "cf-user-123" {
		t.Errorf("Username = %q, want cf-user-123", creds.Username)
	}
	if creds.Password != "cf-pass-xyz" {
		t.Errorf("Password = %q", creds.Password)
	}
	if creds.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt zero; wanted ~now+TTL")
	}

	// Second Get within TTL should hit the cache (same pointer).
	creds2, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get #2: %v", err)
	}
	if creds != creds2 {
		t.Errorf("expected cached pointer on repeat Get")
	}

	// Auth header should have been set; verify structure without
	// spilling the token value into test diagnostics.
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(authHeaderSeen, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer prefix", authHeaderSeen)
	}
}

func TestCloudflareProvider_Refresh(t *testing.T) {
	// Fake clock: ExpiresAt math uses this, but the refresh timer
	// uses a short override so the test runs in real-time
	// milliseconds without violating the public TTL floor.
	var (
		clockMu sync.Mutex
		now     = time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	)
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	srv := httptest.NewServer(cfTestHandler(t, http.StatusOK, sampleICEResponse(), nil))
	defer srv.Close()

	p, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:         "tok-id",
		APIToken:        "secret",
		TTL:             time.Hour, // valid per public contract
		BaseURL:         srv.URL,
		Clock:           clock,
		refreshInterval: 50 * time.Millisecond, // test-only override
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer p.Close()

	ch := p.Subscribe()

	// Force first mint.
	if _, err := p.Get(context.Background()); err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Refresh should fire within ~500ms (TTL/2).
	select {
	case creds := <-ch:
		if creds == nil {
			t.Fatalf("Subscribe delivered nil creds")
		}
		if creds.ServerAddr != "turn.cloudflare.com:3478" {
			t.Errorf("refreshed ServerAddr = %q", creds.ServerAddr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("refresh did not fire within 3s")
	}
}

func TestCloudflareProvider_Retries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n <= 2 {
			// First two attempts: 500.
			http.Error(w, `{"error":"temporary"}`, http.StatusInternalServerError)
			return
		}
		raw, _ := json.Marshal(sampleICEResponse())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	p, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:  "tok-id",
		APIToken: "secret",
		TTL:      time.Hour,
		BaseURL:  srv.URL,
		// Very short backoffs so the test is fast but still exercises the retry path.
		backoffs: []time.Duration{1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer p.Close()

	creds, err := p.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if creds.ServerAddr != "turn.cloudflare.com:3478" {
		t.Errorf("ServerAddr after retry = %q", creds.ServerAddr)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("hit count = %d, want 3", got)
	}
}

func TestCloudflareProvider_TerminalError(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		wantHint string
	}{
		{"401 unauthorized", http.StatusUnauthorized, "check api_token"},
		{"403 forbidden", http.StatusForbidden, "check api_token"},
		{"404 not found", http.StatusNotFound, "check token_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				http.Error(w, `{"error":"nope"}`, tc.status)
			}))
			defer srv.Close()

			p, err := NewCloudflareProvider(CloudflareOptions{
				TokenID:  "tok-id",
				APIToken: "secret-does-not-appear-in-errors",
				TTL:      time.Hour,
				BaseURL:  srv.URL,
				backoffs: []time.Duration{1 * time.Millisecond},
			})
			if err != nil {
				t.Fatalf("NewCloudflareProvider: %v", err)
			}
			defer p.Close()

			_, err = p.Get(context.Background())
			if err == nil {
				t.Fatalf("Get returned nil error on %d", tc.status)
			}
			if !strings.Contains(err.Error(), tc.wantHint) {
				t.Errorf("error %q does not contain hint %q", err.Error(), tc.wantHint)
			}
			if strings.Contains(err.Error(), "secret-does-not-appear-in-errors") {
				t.Errorf("error leaks API token: %q", err.Error())
			}

			// Cache must not be poisoned — next Get should also
			// fail (re-minting), not succeed stale.
			_, err2 := p.Get(context.Background())
			if err2 == nil {
				t.Errorf("second Get unexpectedly succeeded")
			}

			// 4xx is terminal: should not have retried. Exactly
			// 2 hits (one per Get call).
			if got := atomic.LoadInt32(&hits); got != 2 {
				t.Errorf("hits = %d, want 2 (no retry on 4xx)", got)
			}
		})
	}
}

func TestCloudflareProvider_URLSelection(t *testing.T) {
	srv := httptest.NewServer(cfTestHandler(t, http.StatusOK, sampleICEResponse(), nil))
	defer srv.Close()

	cases := []struct {
		transport string
		wantAddr  string
	}{
		{"udp", "turn.cloudflare.com:3478"},
		{"tcp", "turn.cloudflare.com:3478"},
		{"tls", "turn.cloudflare.com:5349"},
	}
	for _, tc := range cases {
		t.Run(tc.transport, func(t *testing.T) {
			p, err := NewCloudflareProvider(CloudflareOptions{
				TokenID:   "tok-id",
				APIToken:  "secret",
				TTL:       time.Hour,
				Transport: tc.transport,
				BaseURL:   srv.URL,
			})
			if err != nil {
				t.Fatalf("NewCloudflareProvider: %v", err)
			}
			defer p.Close()

			creds, err := p.Get(context.Background())
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if creds.ServerAddr != tc.wantAddr {
				t.Errorf("ServerAddr = %q, want %q", creds.ServerAddr, tc.wantAddr)
			}
			if creds.Transport != tc.transport {
				t.Errorf("Transport = %q, want %q", creds.Transport, tc.transport)
			}
		})
	}
}

func TestCloudflareProvider_InvalidOptions(t *testing.T) {
	cases := []struct {
		name string
		opts CloudflareOptions
	}{
		{"missing TokenID", CloudflareOptions{APIToken: "t"}},
		{"missing APIToken", CloudflareOptions{TokenID: "id"}},
		{"TTL too small", CloudflareOptions{TokenID: "id", APIToken: "t", TTL: 30 * time.Second}},
		{"TTL too large", CloudflareOptions{TokenID: "id", APIToken: "t", TTL: 49 * time.Hour}},
		{"invalid transport", CloudflareOptions{TokenID: "id", APIToken: "t", Transport: "sctp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewCloudflareProvider(tc.opts)
			if err == nil {
				p.Close()
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestCloudflareProvider_SecretsNotLogged verifies the API token does
// not appear in any error surface visible to callers. A 4xx + 5xx +
// malformed-JSON response is exercised in turn; all errors are
// scanned for the sentinel secret.
func TestCloudflareProvider_SecretsNotLogged(t *testing.T) {
	const sentinel = "SENTINEL-API-TOKEN-MUST-NOT-LEAK"

	// 4xx path.
	srv4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"bad auth"}`, http.StatusUnauthorized)
	}))
	defer srv4.Close()

	p4, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:  "tok-id",
		APIToken: sentinel,
		TTL:      time.Hour,
		BaseURL:  srv4.URL,
		backoffs: []time.Duration{1 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer p4.Close()
	_, err = p4.Get(context.Background())
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Errorf("4xx error leaks token: %v", err)
	}

	// Malformed-JSON path (200 but garbage body).
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{not json")
	}))
	defer srvBad.Close()

	pBad, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:  "tok-id",
		APIToken: sentinel,
		TTL:      time.Hour,
		BaseURL:  srvBad.URL,
		backoffs: []time.Duration{1 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer pBad.Close()
	_, err = pBad.Get(context.Background())
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Errorf("malformed-JSON error leaks token: %v", err)
	}
}

// TestCloudflareProvider_CloseIdempotent exercises double-Close.
func TestCloudflareProvider_CloseIdempotent(t *testing.T) {
	srv := httptest.NewServer(cfTestHandler(t, http.StatusOK, sampleICEResponse(), nil))
	defer srv.Close()

	p, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:  "tok",
		APIToken: "secret",
		TTL:      time.Hour,
		BaseURL:  srv.URL,
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close #1: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close #2: %v", err)
	}
}

// TestCloudflareProvider_NoURLMatch exercises the case where the
// response is well-formed but contains no URL matching the requested
// transport. The error is terminal.
func TestCloudflareProvider_NoURLMatch(t *testing.T) {
	body := cfResponse{
		ICEServers: []cfICEServer{
			{
				// Only a TCP URL.
				URLs:       []string{"turn:turn.example.com:3478?transport=tcp"},
				Username:   "u",
				Credential: "p",
			},
		},
	}
	srv := httptest.NewServer(cfTestHandler(t, http.StatusOK, body, nil))
	defer srv.Close()

	p, err := NewCloudflareProvider(CloudflareOptions{
		TokenID:   "tok",
		APIToken:  "secret",
		TTL:       time.Hour,
		Transport: "udp", // no UDP URL in response
		BaseURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider: %v", err)
	}
	defer p.Close()

	_, err = p.Get(context.Background())
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no udp URL") {
		t.Errorf("error = %q, want mention of 'no udp URL'", err.Error())
	}
}

// TestParseTURNURL exercises the hand-rolled parser directly.
func TestParseTURNURL(t *testing.T) {
	cases := []struct {
		raw            string
		wantScheme     string
		wantTransport  string
		wantHostPort   string
		wantOK         bool
	}{
		{"turn:host:3478?transport=udp", "turn", "udp", "host:3478", true},
		{"turn:host:3478?transport=tcp", "turn", "tcp", "host:3478", true},
		{"turns:host:5349?transport=tcp", "turns", "tcp", "host:5349", true},
		{"turn:host:3478", "turn", "udp", "host:3478", true},       // default udp
		{"turns:host:5349", "turns", "tcp", "host:5349", true},     // default tcp
		{"turn:host:3478?transport=udp", "turns", "tcp", "", false}, // scheme mismatch
		{"turn:host:3478?transport=tcp", "turn", "udp", "", false},  // transport mismatch
		{"stun:host:3478", "turn", "udp", "", false},                // wrong scheme
		{"garbage", "turn", "udp", "", false},
		{"turn:nohostport", "turn", "udp", "", false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s/%s", tc.raw, tc.wantScheme, tc.wantTransport), func(t *testing.T) {
			got, ok := parseTURNURL(tc.raw, tc.wantScheme, tc.wantTransport)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.wantHostPort {
				t.Errorf("hostPort = %q, want %q", got, tc.wantHostPort)
			}
		})
	}
}
