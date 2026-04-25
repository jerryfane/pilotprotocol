package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/rendezvous"
)

// rendezvousStub captures Publish PUTs and serves a fixed reply
// for Lookup GETs. We don't reuse the real cmd/pilot-rendezvous
// server here because that would create a test-only import cycle
// (this test lives in pkg/daemon, the server in cmd/pilot-rendezvous).
type rendezvousStub struct {
	mu        sync.Mutex
	puts      []rendezvous.AnnounceBlob
	getResult map[uint32]*rendezvous.AnnounceBlob
}

func (s *rendezvousStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			var blob rendezvous.AnnounceBlob
			if err := decodeJSON(r, &blob); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.puts = append(s.puts, blob)
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			id := parseNodeIDFromPath(r.URL.Path)
			s.mu.Lock()
			blob, ok := s.getResult[id]
			s.mu.Unlock()
			if !ok || blob == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = encodeJSON(w, blob)
		default:
			http.Error(w, "no", http.StatusMethodNotAllowed)
		}
	})
}

// putCount returns how many PUTs the stub has received. Take a
// snapshot under the lock so concurrent writers don't make the
// test flake.
func (s *rendezvousStub) putCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts)
}

// TestRendezvous_DisabledByEmptyURL: when Config.RendezvousURL
// is empty, the daemon constructs no client, the publish loop
// returns immediately, and the dial-side helper is a no-op.
// This is the load-bearing "operator opt-out" guarantee.
func TestRendezvous_DisabledByEmptyURL(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	if d.rendezvousClient != nil {
		t.Fatalf("rendezvousClient should be nil with empty URL")
	}
	if d.rendezvousPublishCh != nil {
		t.Fatalf("rendezvousPublishCh should be nil with empty URL")
	}
	// Publish loop returns immediately on empty config:
	done := make(chan struct{})
	go func() {
		d.rendezvousPublishLoop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("rendezvousPublishLoop didn't return for empty URL")
	}
	// Lookup helper is a no-op:
	if got := d.rendezvousLookupForDial(123); got != "" {
		t.Fatalf("rendezvousLookupForDial returned %q with no client", got)
	}
}

// TestRendezvous_ClientConstructedWhenURLSet: the daemon honours
// a non-empty URL by wiring up the client + channel. (The
// channel is the contract surface for the rotation hook.)
func TestRendezvous_ClientConstructedWhenURLSet(t *testing.T) {
	d := New(Config{
		Email:         "test@example.com",
		RendezvousURL: "https://rendezvous.example.com",
	})
	if d.rendezvousClient == nil {
		t.Fatalf("rendezvousClient should be non-nil with URL set")
	}
	if d.rendezvousPublishCh == nil {
		t.Fatalf("rendezvousPublishCh should be non-nil with URL set")
	}
}

// TestRendezvous_PublishLoop_PublishesIncomingAddrs: the loop
// drains the channel and delegates to the rendezvous client.
// We verify by pointing the client at a stub and asserting the
// PUT history matches what we fed.
func TestRendezvous_PublishLoop_PublishesIncomingAddrs(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	d := New(Config{
		Email:         "test@example.com",
		RendezvousURL: srv.URL,
	})
	d.identity = id
	d.setNodeIDForTest(45491)

	stopWhenDone := make(chan struct{})
	go func() {
		d.rendezvousPublishLoop()
		close(stopWhenDone)
	}()

	d.rendezvousPublishCh <- "104.30.150.206:49529"
	waitForCondition(t, 2*time.Second, func() bool {
		return stub.putCount() >= 1
	})

	close(d.stopCh)
	select {
	case <-stopWhenDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("rendezvousPublishLoop didn't exit after stopCh close")
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.puts) != 1 {
		t.Fatalf("stub saw %d PUTs, want 1", len(stub.puts))
	}
	got := stub.puts[0]
	if got.NodeID != 45491 {
		t.Fatalf("PUT NodeID: %d, want 45491", got.NodeID)
	}
	if got.TURNEndpoint != "104.30.150.206:49529" {
		t.Fatalf("PUT endpoint: %q", got.TURNEndpoint)
	}
}

// TestRendezvous_PublishLoop_DropsBeforeNodeID: a rotation
// event that fires before nodeID is assigned must be silently
// dropped (we have nothing meaningful to publish under).
func TestRendezvous_PublishLoop_DropsBeforeNodeID(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	id, _ := crypto.GenerateIdentity()
	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	d.identity = id
	// Don't set nodeID — leave it 0.

	go d.rendezvousPublishLoop()
	d.rendezvousPublishCh <- "1.2.3.4:5"
	time.Sleep(150 * time.Millisecond)
	close(d.stopCh)

	if stub.putCount() != 0 {
		t.Fatalf("stub saw %d PUTs before nodeID was assigned (want 0)",
			stub.putCount())
	}
}

// TestRendezvous_PublishLoop_LastValueWins: rotation events
// outrun the network. The publish channel buffers length 1; the
// rotation hook overwrites stale values rather than blocking.
// This test fires several events back-to-back and checks the
// final published address is the latest.
func TestRendezvous_PublishLoop_LastValueWins(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	// Add a hand-built artificial delay to the stub by wrapping
	// the handler in a slower one.
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		stub.handler().ServeHTTP(w, r)
	})
	srv := httptest.NewServer(slow)
	defer srv.Close()

	id, _ := crypto.GenerateIdentity()
	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	d.identity = id
	d.setNodeIDForTest(7)

	go d.rendezvousPublishLoop()

	// Simulate the SetTURNOnLocalAddrChange callback firing
	// rapidly N times: the channel is length 1, we push then
	// drain-and-push each time.
	addrs := []string{"a:1", "b:2", "c:3", "d:4"}
	for _, a := range addrs {
		select {
		case d.rendezvousPublishCh <- a:
		default:
			// channel full — emulate the production branch
			select {
			case <-d.rendezvousPublishCh:
			default:
			}
			select {
			case d.rendezvousPublishCh <- a:
			default:
			}
		}
	}

	// Wait long enough that the loop drained whatever's in the
	// channel and the slow stub has handled the request(s).
	time.Sleep(300 * time.Millisecond)
	close(d.stopCh)

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.puts) == 0 {
		t.Fatalf("stub saw 0 PUTs; want >=1")
	}
	final := stub.puts[len(stub.puts)-1]
	if final.TURNEndpoint != "d:4" {
		t.Fatalf("final published endpoint: %q, want %q", final.TURNEndpoint, "d:4")
	}
}

// TestRendezvous_LookupForDial_ReturnsFreshEndpoint: the dial-
// side helper queries the rendezvous and returns a non-empty
// endpoint when the rendezvous has a record that differs from
// the cached path.
func TestRendezvous_LookupForDial_ReturnsFreshEndpoint(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	id, _ := crypto.GenerateIdentity()
	now := time.Now()
	blob, err := rendezvous.Sign(id, 999, "11.22.33.44:443", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	stub.mu.Lock()
	stub.getResult[999] = blob
	stub.mu.Unlock()

	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	got := d.rendezvousLookupForDial(999)
	if got != "11.22.33.44:443" {
		t.Fatalf("rendezvousLookupForDial: %q, want 11.22.33.44:443", got)
	}
}

// TestRendezvous_LookupForDial_ReturnsEmptyOnSameAsCached: if
// the rendezvous response matches the cached endpoint, we don't
// reinstall — empty return tells the dial loop to proceed.
func TestRendezvous_LookupForDial_ReturnsEmptyOnSameAsCached(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	id, _ := crypto.GenerateIdentity()
	now := time.Now()
	blob, _ := rendezvous.Sign(id, 555, "10.20.30.40:443", now, 5*time.Minute)
	stub.mu.Lock()
	stub.getResult[555] = blob
	stub.mu.Unlock()

	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	// Pre-install the same endpoint into the path table.
	if err := d.tunnels.AddPeerTURNEndpoint(555, "10.20.30.40:443"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	got := d.rendezvousLookupForDial(555)
	if got != "" {
		t.Fatalf("rendezvousLookupForDial returned %q for cache-equal endpoint (want empty)", got)
	}
}

// TestRendezvous_LookupForDial_ReturnsEmptyOn404: a peer the
// rendezvous has never heard of yields empty return — exactly
// what the dial loop expects ("no fresh data, fall back to
// existing behaviour").
func TestRendezvous_LookupForDial_ReturnsEmptyOn404(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	if got := d.rendezvousLookupForDial(424242); got != "" {
		t.Fatalf("rendezvousLookupForDial returned %q for 404 (want empty)", got)
	}
}

// TestRendezvous_LookupForDial_ReturnsEmptyOnTransportError:
// errors are swallowed at Debug; the dial loop continues.
func TestRendezvous_LookupForDial_ReturnsEmptyOnTransportError(t *testing.T) {
	d := New(Config{
		Email:         "test@example.com",
		RendezvousURL: "http://127.0.0.1:1", // unreachable
	})
	if got := d.rendezvousLookupForDial(1); got != "" {
		t.Fatalf("rendezvousLookupForDial returned %q on transport error (want empty)", got)
	}
}

// TestRendezvous_PeerTURNEndpoint: round-trip the helper that
// the dial loop uses to decide "is this lookup result fresh?".
// Trivial; included so a refactor that breaks the helper's
// nil-handling is caught.
func TestRendezvous_PeerTURNEndpoint(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if got := tm.PeerTURNEndpoint(999); got != "" {
		t.Fatalf("PeerTURNEndpoint of unknown node: %q", got)
	}
	if err := tm.AddPeerTURNEndpoint(999, "1.2.3.4:5"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	if got := tm.PeerTURNEndpoint(999); got != "1.2.3.4:5" {
		t.Fatalf("PeerTURNEndpoint: %q, want 1.2.3.4:5", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// setNodeIDForTest sets d.nodeID under the addrMu RWMutex so the
// publish loop's RLock-read sees it. We use this instead of
// running a full daemon Start (which would require a registry,
// listener, etc.).
func (d *Daemon) setNodeIDForTest(id uint32) {
	d.addrMu.Lock()
	d.nodeID = id
	d.addrMu.Unlock()
}

// waitForCondition polls cond every 10 ms until it returns true
// or timeout elapses.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition didn't become true within %s", timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
func encodeJSON(w http.ResponseWriter, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

// parseNodeIDFromPath does the same parse the real server does;
// inlined to keep this test self-contained.
func parseNodeIDFromPath(path string) uint32 {
	const prefix = "/v1/announce/"
	if !strings.HasPrefix(path, prefix) {
		return 0
	}
	rest := path[len(prefix):]
	var n uint64
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return uint32(n)
}

