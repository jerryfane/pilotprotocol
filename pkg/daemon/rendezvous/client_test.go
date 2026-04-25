package rendezvous

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubServer is the minimum reasonable rendezvous emulation: an
// in-memory map keyed by NodeID with PUT/GET handlers. We
// intentionally don't share code with cmd/pilot-rendezvous here
// — the goal is for the *client* tests to be honest about what
// they're talking to. cmd/pilot-rendezvous gets its own tests.
type stubServer struct {
	mu    sync.Mutex
	store map[uint32]AnnounceBlob
	puts  []AnnounceBlob // history, in arrival order
	gets  []uint32
}

func newStubServer() (*stubServer, *httptest.Server) {
	s := &stubServer{store: map[uint32]AnnounceBlob{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/announce/", func(w http.ResponseWriter, r *http.Request) {
		idStr := strings.TrimPrefix(r.URL.Path, "/v1/announce/")
		id64, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			http.Error(w, "bad node id", http.StatusBadRequest)
			return
		}
		nodeID := uint32(id64)
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			var blob AnnounceBlob
			if err := json.Unmarshal(body, &blob); err != nil {
				http.Error(w, "unmarshal", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.store[nodeID] = blob
			s.puts = append(s.puts, blob)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			s.mu.Lock()
			blob, ok := s.store[nodeID]
			s.gets = append(s.gets, nodeID)
			s.mu.Unlock()
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(blob)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	return s, httptest.NewServer(mux)
}

// TestClient_PublishLookupRoundTrip is the integration smoke
// test: a daemon publishes its endpoint, a peer queries the
// same NodeID, and the returned endpoint matches what the
// publisher signed. This is the entire steady-state contract
// of jf.14.
func TestClient_PublishLookupRoundTrip(t *testing.T) {
	stub, srv := newStubServer()
	defer srv.Close()

	id := freshIdentity(t)
	c := New(srv.URL)

	if err := c.Publish(id, 45491, "104.30.150.206:49529"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	stub.mu.Lock()
	if len(stub.puts) != 1 {
		t.Fatalf("server saw %d PUTs, want 1", len(stub.puts))
	}
	stub.mu.Unlock()

	got, err := c.Lookup(45491, nil)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "104.30.150.206:49529" {
		t.Fatalf("Lookup returned %q, want %q", got, "104.30.150.206:49529")
	}
}

// TestClient_LookupExpectedPubkey_Mismatch: when the caller
// supplies a roster-bound expected public key (jf.15+ mode)
// and the server hands back a blob signed by a different key,
// Lookup must fail and return an empty endpoint. This is the
// integrity boundary that justifies a future jf.15 leaning on
// a roster.
func TestClient_LookupExpectedPubkey_Mismatch(t *testing.T) {
	_, srv := newStubServer()
	defer srv.Close()
	id1 := freshIdentity(t)
	id2 := freshIdentity(t)
	c := New(srv.URL)
	if err := c.Publish(id1, 1, "1.2.3.4:5678"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := c.Lookup(1, id2.PublicKey)
	if err == nil {
		t.Fatalf("Lookup accepted blob signed by id1 under expected=id2")
	}
	if got != "" {
		t.Fatalf("Lookup returned endpoint %q on verify failure (must be empty)", got)
	}
}

// TestClient_Lookup_NotFound: missing record yields ("", nil),
// not an error. Caller distinguishes "peer hasn't published"
// from "transport failed" by error vs empty.
func TestClient_Lookup_NotFound(t *testing.T) {
	_, srv := newStubServer()
	defer srv.Close()
	c := New(srv.URL)
	got, err := c.Lookup(99999, nil)
	if err != nil {
		t.Fatalf("Lookup of unknown NodeID returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("Lookup of unknown NodeID returned %q, want empty", got)
	}
}

// TestClient_Lookup_TamperedBlobOnTheWire: a malicious or buggy
// server returning an altered blob (different endpoint, same
// signature) must be detected by client-side Verify. Otherwise
// the rendezvous's "trusted for availability, not integrity"
// posture collapses.
func TestClient_Lookup_TamperedBlobOnTheWire(t *testing.T) {
	stub, srv := newStubServer()
	defer srv.Close()
	id := freshIdentity(t)
	c := New(srv.URL)
	if err := c.Publish(id, 1, "1.2.3.4:5678"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Tamper with the stored blob: keep its signature but
	// substitute a different endpoint.
	stub.mu.Lock()
	b := stub.store[1]
	b.TURNEndpoint = "evil.example.com:9999"
	stub.store[1] = b
	stub.mu.Unlock()

	_, err := c.Lookup(1, nil)
	if err == nil {
		t.Fatalf("Lookup accepted tampered blob")
	}
}

// TestClient_PublishURL_TrailingSlashStripped: a URL passed
// with or without a trailing slash should produce identical
// requests. Tiny ergonomic correctness.
func TestClient_PublishURL_TrailingSlashStripped(t *testing.T) {
	_, srv := newStubServer()
	defer srv.Close()
	id := freshIdentity(t)
	c := New(srv.URL + "/")
	if err := c.Publish(id, 1, "1.2.3.4:5678"); err != nil {
		t.Fatalf("Publish with trailing slash URL: %v", err)
	}
}

// TestClient_PublishLatestWins: two Publish calls with
// different endpoints — the second overwrites the first and
// Lookup returns the newer endpoint. Captures the rotation
// flow at the protocol level.
func TestClient_PublishLatestWins(t *testing.T) {
	_, srv := newStubServer()
	defer srv.Close()
	id := freshIdentity(t)
	c := New(srv.URL)

	// Use a fake clock so the second Publish can carry a strictly
	// later IssuedAt than the first. (Real Sign uses wall-clock
	// ms, which on a fast machine could collide.)
	t0 := time.Date(2026, 4, 25, 19, 30, 0, 0, time.UTC)
	c.Now = func() time.Time { return t0 }
	if err := c.Publish(id, 7, "1.1.1.1:1111"); err != nil {
		t.Fatalf("Publish #1: %v", err)
	}
	c.Now = func() time.Time { return t0.Add(2 * time.Second) }
	if err := c.Publish(id, 7, "2.2.2.2:2222"); err != nil {
		t.Fatalf("Publish #2: %v", err)
	}
	got, err := c.Lookup(7, nil)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "2.2.2.2:2222" {
		t.Fatalf("Lookup after second Publish returned %q, want 2.2.2.2:2222", got)
	}
}

// TestClient_NoURL: an empty-URL Client must refuse to do
// anything (rather than panic on http.NewRequest). The daemon
// constructs the Client even when the rendezvous is disabled;
// the loops are no-ops, but it's worth documenting.
func TestClient_NoURL(t *testing.T) {
	c := &Client{URL: "", HTTP: &http.Client{Timeout: 1 * time.Second}}
	id := freshIdentity(t)
	if err := c.Publish(id, 1, "1.2.3.4:5"); err == nil {
		t.Fatalf("Publish with empty URL accepted")
	}
	if _, err := c.Lookup(1, nil); err == nil {
		t.Fatalf("Lookup with empty URL accepted")
	}
}

// TestClient_PublishHandles5xx: the server returning 5xx must
// surface as an error (not silently succeed). We rebuild a
// minimal handler since the stub doesn't model errors.
func TestClient_PublishHandles5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	id := freshIdentity(t)
	c := New(srv.URL)
	err := c.Publish(id, 1, "1.2.3.4:5")
	if err == nil {
		t.Fatalf("Publish accepted 500 response")
	}
}

// Sanity: ed25519.PublicKey type assertion correctness for
// when we compare keys in tests above. This verifies the
// identity package and our blob package are in sync.
func TestIdentity_PublicKeyType(t *testing.T) {
	id := freshIdentity(t)
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("PublicKey size: %d", len(id.PublicKey))
	}
	// Round-trip via canonicalPayload to make sure the type
	// flows correctly into Sign.
	_ = canonicalPayload(1, id.PublicKey, "x", 1, 2)
}

// failureMode used to ensure errors include the URL — useful
// when debugging deployments.
func TestClient_ErrorIncludesURL(t *testing.T) {
	id := freshIdentity(t)
	c := New("http://127.0.0.1:1") // intentionally unreachable
	err := c.Publish(id, 1, "1.2.3.4:5")
	if err == nil {
		t.Fatalf("expected error from unreachable rendezvous")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error missing URL: %v", err)
	}
	_, err = c.Lookup(1, nil)
	if err == nil {
		t.Fatalf("expected error on Lookup against unreachable rendezvous")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("Lookup error missing URL: %v", err)
	}
	_ = fmt.Sprint(err) // keep fmt import if it ever becomes unused
}
