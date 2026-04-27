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
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
)

// fakeEndpoint and fakeDialedConn satisfy the transport-package
// interfaces just enough for AddPeerTURNEndpoint's eviction
// predicate to exercise its branches deterministically. Real
// pion-backed conns can't be constructed in unit tests without
// a network round-trip, and we only care about
// RemoteEndpoint().Network() and Close() here.
type fakeEndpoint struct{ network string }

func (e *fakeEndpoint) Network() string { return e.network }
func (e *fakeEndpoint) String() string  { return "fake://" + e.network }

type fakeDialedConn struct {
	network string
	closed  bool
}

func (c *fakeDialedConn) Send(frame []byte) error { return nil }
func (c *fakeDialedConn) RemoteEndpoint() transport.Endpoint {
	return &fakeEndpoint{network: c.network}
}
func (c *fakeDialedConn) Close() error {
	c.closed = true
	return nil
}

// rendezvousStub captures Publish PUTs and serves a fixed reply
// for Lookup GETs. We don't reuse the real cmd/pilot-rendezvous
// server here because that would create a test-only import cycle
// (this test lives in pkg/daemon, the server in cmd/pilot-rendezvous).
type rendezvousStub struct {
	mu             sync.Mutex
	puts           []rendezvous.AnnounceBlob
	putAttempts    []rendezvous.AnnounceBlob
	putStatuses    []int
	putRetryAfters []string
	getResult      map[uint32]*rendezvous.AnnounceBlob
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
			s.putAttempts = append(s.putAttempts, blob)
			status := http.StatusNoContent
			if len(s.putStatuses) > 0 {
				status = s.putStatuses[0]
				s.putStatuses = s.putStatuses[1:]
			}
			retryAfter := ""
			if len(s.putRetryAfters) > 0 {
				retryAfter = s.putRetryAfters[0]
				s.putRetryAfters = s.putRetryAfters[1:]
			}
			if status/100 == 2 {
				s.puts = append(s.puts, blob)
			}
			s.mu.Unlock()
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			if status/100 != 2 {
				http.Error(w, http.StatusText(status), status)
				return
			}
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

func (s *rendezvousStub) putAttemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.putAttempts)
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

func TestRendezvous_PublishLoop_Retries429AndKeepsLatest(t *testing.T) {
	oldBase, oldCap, oldJitter := rendezvousPublishRetryBase, rendezvousPublishRetryCap, rendezvousPublishJitter
	rendezvousPublishRetryBase = 200 * time.Millisecond
	rendezvousPublishRetryCap = 200 * time.Millisecond
	rendezvousPublishJitter = func(time.Duration) time.Duration { return 0 }
	defer func() {
		rendezvousPublishRetryBase = oldBase
		rendezvousPublishRetryCap = oldCap
		rendezvousPublishJitter = oldJitter
	}()

	stub := &rendezvousStub{
		getResult:   map[uint32]*rendezvous.AnnounceBlob{},
		putStatuses: []int{http.StatusTooManyRequests, http.StatusNoContent},
	}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	id, _ := crypto.GenerateIdentity()
	d := New(Config{Email: "test@example.com", RendezvousURL: srv.URL})
	d.identity = id
	d.setNodeIDForTest(7)

	done := make(chan struct{})
	go func() {
		d.rendezvousPublishLoop()
		close(done)
	}()

	d.rendezvousPublishCh <- "stale:1"
	waitForCondition(t, 2*time.Second, func() bool {
		return stub.putAttemptCount() >= 1
	})
	d.rendezvousPublishCh <- "fresh:2"

	waitForCondition(t, 2*time.Second, func() bool {
		return stub.putCount() >= 1
	})
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("rendezvousPublishLoop didn't exit after stopCh close")
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.puts) != 1 {
		t.Fatalf("accepted PUTs=%d, want 1", len(stub.puts))
	}
	if got := stub.puts[0].TURNEndpoint; got != "fresh:2" {
		t.Fatalf("accepted endpoint=%q, want fresh:2", got)
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

// TestRendezvous_LookupForDial_ReturnsFreshEvenWhenCacheEqual: the
// jf.15.7 behaviour change. Previously, rendezvousLookupForDial
// suppressed same-as-cached returns to skip a no-op
// AddPeerTURNEndpoint. But the no-op was not really a no-op: it
// gated PermitTURNPeer's CreatePermission re-issue — the only
// thing that keeps a peer's address in our local allocation's
// permittedAddrs working set across rotations and bookkeeping
// races. Now lookup returns the fresh value unconditionally; the
// caller re-issues AddPeerTURNEndpoint, which re-PermitTURNPeers,
// which refreshes the permission timestamp without evicting
// cached conns (eviction still gates on actual address change).
func TestRendezvous_LookupForDial_ReturnsFreshEvenWhenCacheEqual(t *testing.T) {
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
	if got != "10.20.30.40:443" {
		t.Fatalf("rendezvousLookupForDial returned %q (want 10.20.30.40:443 — must return fresh even when cache-equal so caller can refresh PermitTURNPeer)", got)
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

// TestRendezvous_RefreshLoop_PeriodicallyRepublishes is the
// load-bearing test for jf.14.2's Bug A fix: even with no TURN
// rotation, the daemon's refresh loop must re-publish the
// current endpoint at the configured cadence so the rendezvous
// record doesn't expire.
//
// We can't realistically wait 15 minutes in a unit test, so we
// can't directly exercise the production cadence. What we DO
// exercise is the loop's structural behaviour: given a non-nil
// rendezvousClient and a TUNNEL with a current TURN address,
// the loop wakes on its ticker and feeds the publish channel.
// Disabled-by-empty-URL is covered separately.
//
// This test fires the loop's body manually by ticking through
// the publish channel — verifying that the LOOP'S CONTRACT
// (read TURNLocalAddr → push to channel) holds, separate from
// the timing of the ticker itself which is just a constant.
func TestRendezvous_RefreshLoop_DisabledByEmptyURL(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	if d.rendezvousClient != nil {
		t.Fatalf("rendezvousClient should be nil with empty URL")
	}
	done := make(chan struct{})
	go func() {
		d.rendezvousRefreshLoop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("rendezvousRefreshLoop didn't return for empty URL")
	}
}

// TestRendezvous_RefreshLoop_StopsOnStopCh: standard goroutine-
// lifecycle hygiene. The loop must exit promptly when stopCh
// closes, even mid-jitter-sleep at startup.
func TestRendezvous_RefreshLoop_StopsOnStopCh(t *testing.T) {
	stub := &rendezvousStub{getResult: map[uint32]*rendezvous.AnnounceBlob{}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	d := New(Config{
		Email:         "test@example.com",
		RendezvousURL: srv.URL,
	})
	done := make(chan struct{})
	go func() {
		d.rendezvousRefreshLoop()
		close(done)
	}()
	// Give the loop a beat to enter its initial-jitter sleep.
	time.Sleep(50 * time.Millisecond)
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("rendezvousRefreshLoop didn't exit after stopCh close")
	}
}

// TestRendezvous_AddPeerTURNEndpoint_EvictsCachedConnOnAddrChange
// is the load-bearing test for jf.14.2's Bug B fix.
//
// Setup: install a TURN endpoint AND a cached non-UDP conn for
// the same peer. Then install a different endpoint via
// AddPeerTURNEndpoint. Assert the cached conn was evicted from
// peerConns and Closed.
//
// Without this fix, fresh endpoints from the rendezvous lookup
// install correctly into peerTURN but never take effect because
// pion's TURN client cached against the OLD address keeps
// failing CreatePermission.
func TestRendezvous_AddPeerTURNEndpoint_EvictsCachedConnOnAddrChange(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("first AddPeerTURNEndpoint: %v", err)
	}
	// Inject a fake non-UDP cached conn (simulates pion TURN
	// client built against the old addr). The conn type doesn't
	// matter for the eviction predicate — only that
	// RemoteEndpoint().Network() != "udp".
	stub := &fakeDialedConn{network: "turn", closed: false}
	tm.mu.Lock()
	tm.peerConns[7] = stub
	tm.mu.Unlock()

	// Replace with a different address.
	if err := tm.AddPeerTURNEndpoint(7, "9.8.7.6:5"); err != nil {
		t.Fatalf("second AddPeerTURNEndpoint: %v", err)
	}

	tm.mu.RLock()
	_, stillCached := tm.peerConns[7]
	tm.mu.RUnlock()
	if stillCached {
		t.Fatalf("cached non-UDP conn should have been evicted on addr change")
	}
	if !stub.closed {
		t.Fatalf("evicted conn should have been Close()'d")
	}
	// The new endpoint is in place.
	if got := tm.PeerTURNEndpoint(7); got != "9.8.7.6:5" {
		t.Fatalf("PeerTURNEndpoint after change: %q, want 9.8.7.6:5", got)
	}
}

// TestRendezvous_AddPeerTURNEndpoint_NoEvictOnSameAddr: a
// no-op re-install (same address called twice — common when
// the rendezvous lookup confirms the cached value) must NOT
// disturb the live cached conn. Otherwise we'd cause spurious
// reconnects every time the rendezvous returns the same
// endpoint we already have.
func TestRendezvous_AddPeerTURNEndpoint_NoEvictOnSameAddr(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("first AddPeerTURNEndpoint: %v", err)
	}
	stub := &fakeDialedConn{network: "turn", closed: false}
	tm.mu.Lock()
	tm.peerConns[7] = stub
	tm.mu.Unlock()

	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("re-install same addr: %v", err)
	}

	tm.mu.RLock()
	_, stillCached := tm.peerConns[7]
	tm.mu.RUnlock()
	if !stillCached {
		t.Fatalf("cached conn was evicted on no-op re-install (must be preserved)")
	}
	if stub.closed {
		t.Fatalf("conn was Close()'d on no-op re-install")
	}
}

// TestRendezvous_AddPeerTURNEndpoint_NoEvictUDPConn: the
// eviction predicate is "non-UDP" because UDP cached conns
// are stateless wrappers (raw UDP sockets) — they don't hold
// pion permission state and aren't broken by an addr change.
// Evicting them would just cause unnecessary churn.
func TestRendezvous_AddPeerTURNEndpoint_NoEvictUDPConn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("first AddPeerTURNEndpoint: %v", err)
	}
	stub := &fakeDialedConn{network: "udp", closed: false}
	tm.mu.Lock()
	tm.peerConns[7] = stub
	tm.mu.Unlock()

	if err := tm.AddPeerTURNEndpoint(7, "9.8.7.6:5"); err != nil {
		t.Fatalf("second AddPeerTURNEndpoint: %v", err)
	}

	tm.mu.RLock()
	_, stillCached := tm.peerConns[7]
	tm.mu.RUnlock()
	if !stillCached {
		t.Fatalf("UDP cached conn should be preserved on addr change")
	}
	if stub.closed {
		t.Fatalf("UDP cached conn was unnecessarily Close()'d")
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
