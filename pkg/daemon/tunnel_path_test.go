package daemon

import (
	"net"
	"testing"
)

// The tests below lock down the v1.9.0-jf.4 reply-on-ingress routing
// invariants. They operate directly on a TunnelManager without
// starting the UDP socket or running dispatchLoop; that's sufficient
// because the invariants we care about live in the per-peer path map
// and the public API (SetRelayPeer / IsRelayPeer / HasPeer / PeerList).

func TestPeerPath_SetRelayPeerFlipsViaRelay(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 42

	if tm.IsRelayPeer(peer) {
		t.Fatalf("fresh peer should not be relay before any signal")
	}

	tm.SetRelayPeer(peer, true)
	if !tm.IsRelayPeer(peer) {
		t.Fatalf("after SetRelayPeer(true), IsRelayPeer must be true")
	}
	if !tm.HasPeer(peer) {
		t.Fatalf("setting relay status implies the peer exists in paths")
	}

	tm.SetRelayPeer(peer, false)
	if tm.IsRelayPeer(peer) {
		t.Fatalf("after SetRelayPeer(false), IsRelayPeer must be false")
	}
}

func TestPeerPath_AddPeerSeedsDirectAddr(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 7
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 37736}

	tm.AddPeer(peer, addr)

	// paths[peer].direct should now be set; the easiest user-facing
	// probe is PeerList's Endpoint string.
	list := tm.PeerList()
	if len(list) != 1 {
		t.Fatalf("expected 1 peer in list, got %d", len(list))
	}
	if list[0].NodeID != peer {
		t.Fatalf("wrong node_id in list: %d", list[0].NodeID)
	}
	if list[0].Endpoint != addr.String() {
		t.Fatalf("expected Endpoint=%s, got %s", addr, list[0].Endpoint)
	}
	if list[0].Relay {
		t.Fatalf("AddPeer must not touch viaRelay")
	}
}

func TestPeerPath_UpdatePathDirectThenRelay(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 11
	direct := &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 37736}

	// Simulate an authenticated direct decrypt.
	tm.mu.Lock()
	tm.updatePathDirect(peer, direct)
	tm.mu.Unlock()

	if tm.IsRelayPeer(peer) {
		t.Fatalf("after direct decrypt, viaRelay must be false")
	}
	list := tm.PeerList()
	if len(list) != 1 || list[0].Endpoint != direct.String() {
		t.Fatalf("direct endpoint not reflected in PeerList: %+v", list)
	}

	// Now simulate a relay decrypt from the same peer. viaRelay flips
	// but direct stays (crucial for "resume direct if it comes back").
	tm.mu.Lock()
	tm.updatePathRelay(peer)
	tm.mu.Unlock()

	if !tm.IsRelayPeer(peer) {
		t.Fatalf("after relay decrypt, viaRelay must be true")
	}
	list = tm.PeerList()
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}
	if list[0].Endpoint != direct.String() {
		t.Fatalf("relay decrypt must not clobber last-known direct addr: got %s", list[0].Endpoint)
	}
	if !list[0].Relay {
		t.Fatalf("PeerList.Relay must reflect viaRelay=true")
	}
}

func TestPeerPath_RelayDecryptWithoutDirectSurfacesAsRelay(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 33

	// First signal is a relay frame; no direct addr ever seen.
	tm.mu.Lock()
	tm.updatePathRelay(peer)
	tm.mu.Unlock()

	list := tm.PeerList()
	if len(list) != 1 {
		t.Fatalf("list len: %d", len(list))
	}
	if list[0].Endpoint != "(relay)" {
		t.Fatalf(`relay-only peer should surface as "(relay)", got %q`, list[0].Endpoint)
	}
	if !list[0].Relay {
		t.Fatalf("Relay flag must be true")
	}
}

func TestPeerPath_HandleRelayDeliverDoesNotPolluteDirect(t *testing.T) {
	// The historical bug: handleRelayDeliver stored the beacon's
	// address under peers[srcNodeID] as a placeholder. After the
	// refactor, handleRelayDeliver never touches path.direct; only
	// the authenticated decrypt handlers do, and they route through
	// updatePathRelay (which leaves direct alone).
	tm := NewTunnelManager()
	const peer uint32 = 99
	beacon := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9001}
	if err := tm.SetBeaconAddr(beacon.String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	// Feed a minimal well-formed relay-deliver payload: [srcID(4)][empty-inner]
	// With len(payload) < 4 the switch is skipped (no inner decrypt),
	// which matches what would happen for a garbage/too-short relay
	// frame. We only care that tm.paths[peer].direct stays nil.
	frame := make([]byte, 4)
	// srcNodeID little-endian? no, big-endian per the code.
	frame[0] = byte(peer >> 24)
	frame[1] = byte(peer >> 16)
	frame[2] = byte(peer >> 8)
	frame[3] = byte(peer)
	tm.handleRelayDeliver(frame)

	// Path may or may not exist (depends on whether webhook emission
	// creates it). If it exists, direct must be nil.
	tm.mu.RLock()
	p := tm.paths[peer]
	tm.mu.RUnlock()
	if p != nil && p.direct != nil {
		t.Fatalf("handleRelayDeliver must not populate direct: got %v", p.direct)
	}
}

func TestPeerPath_RemovePeerClearsPath(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 55
	tm.AddPeer(peer, &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1})
	if !tm.HasPeer(peer) {
		t.Fatalf("peer should exist after AddPeer")
	}

	tm.RemovePeer(peer)
	if tm.HasPeer(peer) {
		t.Fatalf("peer should not exist after RemovePeer")
	}
}
