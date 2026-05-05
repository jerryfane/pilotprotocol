package daemon

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
)

// TestOutboundTURNOnly_StartupFailsWithoutTurnProvider pins the fail-closed
// contract: enabling OutboundTURNOnly without TURNProvider MUST refuse to
// start the daemon. Silently degrading to non-relay routing would leak the
// very source IP the flag exists to hide.
func TestOutboundTURNOnly_StartupFailsWithoutTurnProvider(t *testing.T) {
	d := New(Config{
		Email:            "test@example.com",
		OutboundTURNOnly: true,
		TURNProvider:     nil, // explicit: no provider
	})
	err := d.Start()
	if err == nil {
		t.Fatalf("Start() succeeded with -outbound-turn-only but no TURNProvider; want error")
	}
	if !strings.Contains(err.Error(), "outbound-turn-only") {
		t.Fatalf("Start() error = %q; want mention of outbound-turn-only", err)
	}
	if !strings.Contains(err.Error(), "turn-provider") {
		t.Fatalf("Start() error = %q; want remedy mentioning turn-provider", err)
	}
}

// TestWriteFrame_OutboundTURNOnly_UsesCachedTURNConn locks in the primary
// happy path: when OutboundTURNOnly is latched and a cached turn/turn-relay
// conn exists, writeFrame uses it. Nothing about beacon or direct UDP is
// attempted.
func TestWriteFrame_OutboundTURNOnly_UsesCachedTURNConn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.SetOutboundTURNOnly(true)

	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 321
	stub := &stubDialedConn{network: "turn-relay", remote: "203.0.113.200:37500"}
	tm.mu.Lock()
	tm.peerConns[peer] = stub
	// Also latch viaRelay=true so without OutboundTURNOnly the beacon
	// tier would have fired. This test's point: OutboundTURNOnly
	// overrides that.
	tm.paths[peer] = &peerPath{viaRelay: true}
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.mu.Unlock()

	if err := tm.writeFrame(peer, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, []byte("via-turn")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got := stub.sends.Load(); got != 1 {
		t.Fatalf("stub.sends = %d; want 1 (cached turn-relay conn should have been used)", got)
	}
}

// TestWriteFrame_OutboundTURNOnly_RejectsWhenNoTURNPath validates the
// fail-closed semantic at the frame level: if OutboundTURNOnly is set and
// no TURN endpoint / cached conn is available for the peer, writeFrame
// returns an error rather than silently falling back to beacon or direct UDP.
func TestWriteFrame_OutboundTURNOnly_RejectsWhenNoTURNPath(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.SetOutboundTURNOnly(true)

	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 322
	// Set up a beacon + pathDirect that WOULD satisfy writeFrame
	// without OutboundTURNOnly. This test's point: under turn-only,
	// neither tier is allowed.
	tm.mu.Lock()
	tm.paths[peer] = &peerPath{viaRelay: true, direct: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}}
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	// No peerTURN, no cachedConn — no viable TURN path.
	tm.mu.Unlock()

	err := tm.writeFrame(peer, nil, []byte("should-fail"))
	if err == nil {
		t.Fatalf("writeFrame succeeded under OutboundTURNOnly with no TURN path; want error (fail-closed)")
	}
	if !strings.Contains(err.Error(), "outbound-turn-only") {
		t.Fatalf("writeFrame error = %q; want mention of outbound-turn-only", err)
	}
}

// TestWriteFrame_OutboundTURNOnly_SkipsNonTURNCachedConn: even a cached
// conn is rejected if it's not a turn/turn-relay conn. A stale cached TCP
// conn from before OutboundTURNOnly was enabled must not leak source IP.
func TestWriteFrame_OutboundTURNOnly_SkipsNonTURNCachedConn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.SetOutboundTURNOnly(true)

	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 323
	tcpStub := &stubDialedConn{network: "tcp", remote: "203.0.113.1:4443"}
	tm.mu.Lock()
	tm.peerConns[peer] = tcpStub // cached TCP — MUST be skipped in turn-only mode.
	tm.mu.Unlock()

	err := tm.writeFrame(peer, nil, []byte("via-tcp-not-allowed"))
	if err == nil {
		t.Fatalf("writeFrame succeeded with only a TCP cached conn under OutboundTURNOnly; want error")
	}
	if got := tcpStub.sends.Load(); got != 0 {
		t.Fatalf("tcpStub.sends = %d; want 0 (TCP conn must be skipped under OutboundTURNOnly)", got)
	}
}

func TestWriteFrame_OutboundTURNOnly_ResolvesMissingDestinationOnce(t *testing.T) {
	tm := NewTunnelManager()
	defer func() {
		tm.mu.Lock()
		tm.turn = nil
		tm.mu.Unlock()
		tm.Close()
	}()
	tm.SetOutboundTURNOnly(true)
	const peer uint32 = 324
	stub := &stubDialedConn{network: "turn", remote: "203.0.113.200:37500"}
	calls := 0
	tm.SetOutboundTURNOnlyResolver(func(nodeID uint32) error {
		calls++
		if nodeID != peer {
			t.Fatalf("resolver nodeID=%d, want %d", nodeID, peer)
		}
		tm.mu.Lock()
		tm.peerConns[peer] = stub
		tm.mu.Unlock()
		return nil
	})
	tm.mu.Lock()
	tm.turn = &transport.TURNTransport{}
	tm.mu.Unlock()

	if err := tm.writeFrame(peer, nil, []byte("resolved-via-turn")); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if calls != 1 {
		t.Fatalf("resolver calls=%d, want 1", calls)
	}
	if got := stub.sends.Load(); got != 1 {
		t.Fatalf("stub.sends=%d, want 1", got)
	}
}

func TestWriteFrame_OutboundTURNOnly_ResolverFailureStillFailClosed(t *testing.T) {
	tm := NewTunnelManager()
	defer func() {
		tm.mu.Lock()
		tm.turn = nil
		tm.mu.Unlock()
		tm.Close()
	}()
	tm.SetOutboundTURNOnly(true)
	const peer uint32 = 325
	tcpStub := &stubDialedConn{network: "tcp", remote: "203.0.113.1:4443"}
	tm.SetOutboundTURNOnlyResolver(func(uint32) error {
		return errors.New("registry unavailable")
	})
	tm.mu.Lock()
	tm.turn = &transport.TURNTransport{}
	tm.peerConns[peer] = tcpStub
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.paths[peer] = &peerPath{viaRelay: true}
	tm.mu.Unlock()

	err := tm.writeFrame(peer, nil, []byte("must-not-leak"))
	if err == nil {
		t.Fatalf("writeFrame succeeded after resolver failure; want fail-closed error")
	}
	if !strings.Contains(err.Error(), "resolve failed: registry unavailable") {
		t.Fatalf("writeFrame error = %q; want resolver failure", err)
	}
	if got := tcpStub.sends.Load(); got != 0 {
		t.Fatalf("tcpStub.sends=%d, want 0", got)
	}
}

func TestWriteFrame_OutboundTURNOnly_DoesNotUseStaleTCPAfterResolverInstallsTURN(t *testing.T) {
	tm := NewTunnelManager()
	defer func() {
		tm.mu.Lock()
		tm.turn = nil
		tm.mu.Unlock()
		tm.Close()
	}()
	tm.SetOutboundTURNOnly(true)

	const peer uint32 = 326
	tcpStub := &stubDialedConn{network: "tcp", remote: "203.0.113.1:4443"}
	tm.SetOutboundTURNOnlyResolver(func(uint32) error {
		if err := tm.AddPeerTURNEndpoint(peer, "203.0.113.200:37500"); err != nil {
			return err
		}
		return nil
	})
	tm.mu.Lock()
	tm.turn = &transport.TURNTransport{}
	tm.peerConns[peer] = tcpStub
	tm.mu.Unlock()

	err := tm.writeFrame(peer, nil, []byte("must-not-use-tcp"))
	if err == nil {
		t.Fatalf("writeFrame succeeded with fake TURN transport; want fail-closed/no TCP send")
	}
	if got := tcpStub.sends.Load(); got != 0 {
		t.Fatalf("tcpStub.sends=%d, want 0", got)
	}
	tm.mu.RLock()
	gotConn := tm.peerConns[peer]
	tm.mu.RUnlock()
	if gotConn == tcpStub {
		t.Fatalf("stale TCP connection was not evicted")
	}
}

func TestSendFrameViaPeerTURNRoute_EvictsNonTURNCachedConn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	const peer uint32 = 327
	tcpStub := &stubDialedConn{network: "tcp", remote: "203.0.113.1:4443"}
	tm.mu.Lock()
	tm.peerConns[peer] = tcpStub
	tm.mu.Unlock()

	ok, err := tm.sendFrameViaPeerTURNRoute(peer, []byte("must-not-use-tcp"), SendTierOutboundTurnOnlyJF9, false)
	if err != nil {
		t.Fatalf("sendFrameViaPeerTURNRoute err=%v, want nil", err)
	}
	if ok {
		t.Fatalf("sendFrameViaPeerTURNRoute ok=true with stale TCP conn; want false")
	}
	if got := tcpStub.sends.Load(); got != 0 {
		t.Fatalf("tcpStub.sends=%d, want 0", got)
	}
	tm.mu.RLock()
	_, exists := tm.peerConns[peer]
	tm.mu.RUnlock()
	if exists {
		t.Fatalf("stale TCP connection still cached")
	}
}

func TestCommitTURNConnLocked_FirstTURNWinsAndLoserCloses(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	const peer uint32 = 328
	first := &stubDialedConn{network: "turn", remote: "203.0.113.10:37500"}
	second := &stubDialedConn{network: "turn-relay", remote: "203.0.113.11:37500"}

	tm.mu.Lock()
	kept, closeConn := tm.commitTURNConnLocked(peer, first)
	tm.mu.Unlock()
	if kept != first || closeConn != nil {
		t.Fatalf("first commit kept=%v close=%v, want first/nil", kept, closeConn)
	}

	tm.mu.Lock()
	kept, closeConn = tm.commitTURNConnLocked(peer, second)
	tm.mu.Unlock()
	if kept != first || closeConn != second {
		t.Fatalf("second commit kept=%v close=%v, want first/second", kept, closeConn)
	}
	if closeConn != nil {
		_ = closeConn.Close()
	}

	tm.mu.RLock()
	got := tm.peerConns[peer]
	tm.mu.RUnlock()
	if got != first {
		t.Fatalf("cached conn=%v, want first", got)
	}
	if first.closes.Load() != 0 {
		t.Fatalf("first.closes=%d, want 0", first.closes.Load())
	}
	if second.closes.Load() != 1 {
		t.Fatalf("second.closes=%d, want 1", second.closes.Load())
	}
}

func TestCommitTURNConnLocked_ReplacesNonTURNAndClosesOld(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	const peer uint32 = 329
	oldTCP := &stubDialedConn{network: "tcp", remote: "203.0.113.1:4443"}
	newTURN := &stubDialedConn{network: "turn", remote: "203.0.113.10:37500"}
	tm.mu.Lock()
	tm.peerConns[peer] = oldTCP
	kept, closeConn := tm.commitTURNConnLocked(peer, newTURN)
	tm.mu.Unlock()
	if kept != newTURN || closeConn != oldTCP {
		t.Fatalf("commit kept=%v close=%v, want newTURN/oldTCP", kept, closeConn)
	}
	if closeConn != nil {
		_ = closeConn.Close()
	}

	tm.mu.RLock()
	got := tm.peerConns[peer]
	tm.mu.RUnlock()
	if got != newTURN {
		t.Fatalf("cached conn=%v, want newTURN", got)
	}
	if oldTCP.closes.Load() != 1 {
		t.Fatalf("oldTCP.closes=%d, want 1", oldTCP.closes.Load())
	}
	if newTURN.closes.Load() != 0 {
		t.Fatalf("newTURN.closes=%d, want 0", newTURN.closes.Load())
	}
}

// NOTE: writeFrame's jf.11a.2 "send via own relay to peer's real
// address" branch is covered by
// pkg/daemon/transport/turn_ownrelay_test.go (real pion TURN server
// verifying relay.WriteTo reaches an arbitrary UDP peer). The
// writeFrame integration (control flow into SendViaOwnRelay) could
// only be unit-tested here by either (a) spinning up a full pion
// in-process server in the daemon package, which requires
// significant test-helper extraction, or (b) refactoring tm.turn
// to an interface, which is a larger jf.11b/jf.12 concern. For
// jf.11a.2 the control flow is a direct if-else in writeFrame and
// verifiable by code review; the expensive-behavior test lives at
// the transport layer.

// TestWriteFrame_OutboundTURNOnly_Disabled_PreservesDefaultBehavior is the
// regression guard: without OutboundTURNOnly, writeFrame's tier chain is
// unchanged. Beacon relay fires as before.
func TestWriteFrame_OutboundTURNOnly_Disabled_PreservesDefaultBehavior(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	// Explicitly leave OutboundTURNOnly off.

	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 324
	tm.mu.Lock()
	tm.paths[peer] = &peerPath{viaRelay: true}
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.mu.Unlock()

	// With OutboundTURNOnly=false, tier 1 (beacon) should fire.
	// We can't easily observe the beacon packet directly here, but
	// we can assert writeFrame doesn't error out (unlike the
	// fail-closed branch in turn-only mode).
	if err := tm.writeFrame(peer, nil, []byte("default-beacon-path")); err != nil {
		// The actual beacon UDP send may succeed or fail depending
		// on whether the loopback port is reachable. We accept
		// either outcome — the key assertion is that writeFrame
		// didn't return the outbound-turn-only fail-closed error.
		if strings.Contains(err.Error(), "outbound-turn-only") {
			t.Fatalf("writeFrame returned outbound-turn-only error with flag off: %v", err)
		}
	}
}
