package daemon

import (
	"crypto/aes"
	"crypto/cipher"
	"sync"
	"testing"
	"time"
)

// The tests below pin v1.9.0-jf.13's per-peer keepalive contract.
// Background: TURN allocations forward inbound packets only when
// the source IP is on the allocation's permission list (RFC 8656
// §9; permissions IP-only, 5-min lifetime). pion auto-issues
// CreatePermission when the allocation owner SENDS to a peer; if
// the owner is silent toward a particular peer for >5 min, that
// peer's source becomes inadmissible. The keepalive forces a
// periodic outbound to every authenticated peer, refreshing the
// permission on every cycle.

// dummyAEAD is just enough to satisfy the peerCrypto.aead non-nil
// constraint in tests that need to populate ready crypto state.
// We never call its Seal/Open in the tests below; we only need the
// type to be set so AuthenticatedPeerIDs reports a peer ready.
func dummyAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return a
}

// TestAuthenticatedPeerIDs_FiltersByReady verifies the helper
// returns ONLY peers whose crypto state is `ready=true`. Peers
// with crypto entries pending (ready=false) and peers with no
// crypto entry at all must be excluded — the keepalive loop
// shouldn't emit toward peers we can't actually encrypt for.
func TestAuthenticatedPeerIDs_FiltersByReady(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	tm.mu.Lock()
	// Peer A: ready crypto. Should appear.
	tm.crypto[1001] = &peerCrypto{aead: dummyAEAD(t), ready: true}
	// Peer B: crypto entry but not ready (pending key exchange).
	// Must NOT appear.
	tm.crypto[1002] = &peerCrypto{aead: dummyAEAD(t), ready: false}
	// Peer C: nil crypto entry.
	// Must NOT appear.
	tm.crypto[1003] = nil
	// Peer D: ready crypto. Should appear.
	tm.crypto[1004] = &peerCrypto{aead: dummyAEAD(t), ready: true}
	tm.mu.Unlock()

	got := tm.AuthenticatedPeerIDs()
	if len(got) != 2 {
		t.Fatalf("AuthenticatedPeerIDs() returned %d peers; want 2 "+
			"(only ready=true peers should appear). Got: %v",
			len(got), got)
	}

	gotSet := make(map[uint32]bool, len(got))
	for _, id := range got {
		gotSet[id] = true
	}
	if !gotSet[1001] {
		t.Fatalf("peer 1001 (ready) missing from result: %v", got)
	}
	if !gotSet[1004] {
		t.Fatalf("peer 1004 (ready) missing from result: %v", got)
	}
	if gotSet[1002] {
		t.Fatalf("peer 1002 (pending) leaked into result: %v", got)
	}
	if gotSet[1003] {
		t.Fatalf("peer 1003 (nil crypto) leaked into result: %v", got)
	}
}

// TestAuthenticatedPeerIDs_PeerNotInCryptoMap: peers that have a
// path but no crypto entry at all (e.g. AddPeer called but key
// exchange hasn't completed) must NOT appear. Critical: the
// keepalive emit goes through tm.Send, which would queue the frame
// pending crypto and trigger a key exchange — exactly the wrong
// behaviour for a quick periodic probe.
func TestAuthenticatedPeerIDs_PeerNotInCryptoMap(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// Set up a path for peer X but no crypto.
	tm.mu.Lock()
	tm.paths[5555] = &peerPath{}
	tm.mu.Unlock()

	got := tm.AuthenticatedPeerIDs()
	if len(got) != 0 {
		t.Fatalf("AuthenticatedPeerIDs() returned %v; want empty "+
			"(peer with path but no crypto entry must not be a "+
			"keepalive target)", got)
	}
}

// TestAuthenticatedPeerIDs_ConcurrentSafe runs concurrent reads +
// writes against the crypto map under -race to validate the
// RLock-snapshot pattern. The keepalive loop reads under RLock
// while handlers update crypto under Lock — must not race.
func TestAuthenticatedPeerIDs_ConcurrentSafe(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: continuously add/remove crypto entries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			tm.mu.Lock()
			tm.crypto[uint32(i%50)] = &peerCrypto{aead: dummyAEAD(t), ready: true}
			tm.mu.Unlock()
			tm.mu.Lock()
			delete(tm.crypto, uint32((i+25)%50))
			tm.mu.Unlock()
		}
	}()

	// Reader: continuously call AuthenticatedPeerIDs.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = tm.AuthenticatedPeerIDs()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestPeerKeepaliveLoop_DisabledByNegativeInterval pins the
// operator opt-out: if Config.PeerKeepaliveInterval is negative,
// the loop returns immediately without emitting anything.
func TestPeerKeepaliveLoop_DisabledByNegativeInterval(t *testing.T) {
	d := New(Config{
		Email:                 "test@example.com",
		PeerKeepaliveInterval: -1 * time.Second,
	})
	// Confirm the negative interval survived daemon.New (i.e. the
	// "0 → default" path didn't accidentally clobber a negative
	// value).
	if d.config.PeerKeepaliveInterval != -1*time.Second {
		t.Fatalf("daemon.New clobbered negative interval to %v; "+
			"want -1s preserved as the disable signal",
			d.config.PeerKeepaliveInterval)
	}

	// Run the loop in a goroutine. It should return immediately.
	done := make(chan struct{})
	go func() {
		d.peerKeepaliveLoop()
		close(done)
	}()
	select {
	case <-done:
		// good — returned without ticking
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("peerKeepaliveLoop didn't return for negative interval")
	}
}

// TestPeerKeepaliveLoop_DefaultResolved verifies that an unset
// (zero) PeerKeepaliveInterval gets resolved to
// DefaultPeerKeepaliveInterval in daemon.New, NOT left as 0
// (which would silently disable the loop).
func TestPeerKeepaliveLoop_DefaultResolved(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	if d.config.PeerKeepaliveInterval != DefaultPeerKeepaliveInterval {
		t.Fatalf("daemon.New left interval at %v; want %v "+
			"(default 25s should be resolved when caller passes 0)",
			d.config.PeerKeepaliveInterval,
			DefaultPeerKeepaliveInterval)
	}
}

// TestPeerKeepaliveLoop_StopsOnStopCh fires the loop with a tiny
// interval, then closes stopCh, and asserts the goroutine exits
// promptly. Standard goroutine-lifetime hygiene.
func TestPeerKeepaliveLoop_StopsOnStopCh(t *testing.T) {
	d := New(Config{
		Email:                 "test@example.com",
		PeerKeepaliveInterval: 50 * time.Millisecond,
	})

	// We can't directly count ticks in the loop without modifying
	// production code; instead, just verify the goroutine exits
	// within a bounded window after stopCh is closed.
	done := make(chan struct{})
	go func() {
		d.peerKeepaliveLoop()
		close(done)
	}()

	// Let it tick a couple of times (no peers, so each tick is a
	// no-op walk over an empty crypto map).
	time.Sleep(180 * time.Millisecond)
	close(d.stopCh)

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("peerKeepaliveLoop did not exit within 500ms of stopCh close")
	}
}

// TestSendPeerKeepalive_NoTunnelLogsAndReturns: when called for a
// peer that has no path entry (no tunnel to send through),
// sendPeerKeepalive must NOT panic. tm.Send returns an error; the
// keepalive path swallows it at Debug level. Live impact: the
// loop will encounter peers in this state during cold start and
// must not crash the daemon.
func TestSendPeerKeepalive_NoTunnelDoesNotPanic(t *testing.T) {
	d := New(Config{Email: "test@example.com"})
	// No paths, no crypto. sendPeerKeepalive(anything) must just
	// log Debug and return.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sendPeerKeepalive panicked: %v", r)
		}
	}()
	d.sendPeerKeepalive(99999)
}
