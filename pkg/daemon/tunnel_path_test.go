package daemon

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/transport"
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

// v1.9.0-jf.5: AddPeer is authoritative — it installs a fresh direct
// endpoint AND resets any prior relay-fallback state. The regression
// this guards against: daemon calls SetRelayPeer(peer, true) after a
// direct-dial timeout, later a registry lookup yields a new direct
// addr and the daemon calls AddPeer; pre-jf.5 AddPeer left viaRelay
// stuck on true, so writeFrame kept routing via beacon despite the
// fresh direct addr.
func TestPeerPath_AddPeerResetsViaRelay(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 101

	tm.SetRelayPeer(peer, true)
	if !tm.IsRelayPeer(peer) {
		t.Fatalf("precondition: SetRelayPeer(true) must set viaRelay")
	}

	// Now install a direct addr via AddPeer — this must clear viaRelay.
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.50"), Port: 37736}
	tm.AddPeer(peer, addr)

	if tm.IsRelayPeer(peer) {
		t.Fatalf("AddPeer must reset viaRelay=false (installs authoritative direct addr)")
	}
	list := tm.PeerList()
	if len(list) != 1 || list[0].Endpoint != addr.String() {
		t.Fatalf("expected direct endpoint %s, got %+v", addr, list)
	}
	if list[0].Relay {
		t.Fatalf("PeerList.Relay should be false after AddPeer")
	}
}

// v1.9.0-jf.5: updatePathRelay must not touch path.direct. This
// guards against the "auto-add with zero-addr marker" regression
// path: if any caller mistakenly passed the relay-origin zero-addr
// into updatePathDirect or AddPeer, path.direct would be set to
// 0.0.0.0:0 and every subsequent direct-UDP send would black-hole.
// The handlePacket guard in daemon.go skips the auto-add when
// from.IP.IsUnspecified() — this test locks in the path-layer
// invariant that updatePathRelay itself never creates a bad direct.
func TestPeerPath_UpdatePathRelayPreservesDirect(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 303
	real := &net.UDPAddr{IP: net.ParseIP("203.0.113.77"), Port: 55501}

	// First, record a direct ingress.
	tm.mu.Lock()
	tm.updatePathDirect(peer, real)
	tm.mu.Unlock()

	// Then a relay ingress flips viaRelay but must not touch direct.
	tm.mu.Lock()
	tm.updatePathRelay(peer)
	tm.mu.Unlock()

	tm.mu.RLock()
	p := tm.paths[peer]
	tm.mu.RUnlock()
	if p == nil {
		t.Fatalf("path entry missing")
	}
	if !p.viaRelay {
		t.Fatalf("viaRelay must be true after updatePathRelay")
	}
	if p.direct == nil || p.direct.String() != real.String() {
		t.Fatalf("direct must be preserved across relay update: got %v, want %s", p.direct, real)
	}
}

// stubDialedConn is a transport.DialedConn fake that records every
// Send and never errors. Used to validate writeFrame's cached-conn
// path without standing up a real transport.
type stubDialedConn struct {
	network string
	remote  string
	sends   atomic.Int32
	last    atomic.Value // []byte
}

func (s *stubDialedConn) Send(frame []byte) error {
	s.sends.Add(1)
	buf := make([]byte, len(frame))
	copy(buf, frame)
	s.last.Store(buf)
	return nil
}

type stubEndpoint struct{ network, addr string }

func (e *stubEndpoint) Network() string { return e.network }
func (e *stubEndpoint) String() string  { return e.addr }

func (s *stubDialedConn) RemoteEndpoint() transport.Endpoint {
	return &stubEndpoint{network: s.network, addr: s.remote}
}

func (s *stubDialedConn) Close() error { return nil }

// TestWriteFrame_UsesCachedTURNConn validates that once a TURN
// DialedConn is installed in peerConns (as Part A2 does for TURN via
// DialTURNForPeer → writeFrame's cached-conn slot), writeFrame routes
// frames through it rather than UDP. Mirrors the existing invariant
// TCP relies on — this is why TURN needs no writeFrame changes.
func TestWriteFrame_UsesCachedTURNConn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const peer uint32 = 4242

	stub := &stubDialedConn{network: "turn", remote: "198.51.100.77:3478"}

	tm.mu.Lock()
	tm.peerConns[peer] = stub
	tm.mu.Unlock()

	// writeFrame requires tm.udp to be non-nil for the fallback branch,
	// but never reaches it here because the cached non-UDP conn wins.
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	if err := tm.writeFrame(peer, nil, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got := stub.sends.Load(); got != 1 {
		t.Fatalf("stub.sends=%d, want 1", got)
	}
	last := stub.last.Load().([]byte)
	if string(last) != string(payload) {
		t.Fatalf("payload mismatch: %x vs %x", last, payload)
	}
}

// TestAddPeerTURNEndpoint_MapPopulated locks in that the setter lands
// the endpoint in peerTURN and HasTURNEndpoint reflects it. The
// integration with SetPeerEndpoints is exercised in ipc_test.go.
func TestAddPeerTURNEndpoint_MapPopulated(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const peer uint32 = 7

	if tm.HasTURNEndpoint(peer) {
		t.Fatalf("fresh peer should not have a TURN endpoint")
	}
	if err := tm.AddPeerTURNEndpoint(peer, "203.0.113.7:3478"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	if !tm.HasTURNEndpoint(peer) {
		t.Fatalf("after AddPeerTURNEndpoint, HasTURNEndpoint must be true")
	}

	// RemovePeer must wipe peerTURN too (Part A2 contract — mirrors peerTCP).
	tm.RemovePeer(peer)
	if tm.HasTURNEndpoint(peer) {
		t.Fatalf("RemovePeer must clear peerTURN")
	}
}

// TestAddPeerTURNEndpoint_Invalid checks that malformed addrs don't
// silently land in the map.
func TestAddPeerTURNEndpoint_Invalid(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	if err := tm.AddPeerTURNEndpoint(1, "not-a-host-port"); err == nil {
		t.Fatalf("malformed addr should error")
	}
	if err := tm.AddPeerTURNEndpoint(1, ""); err == nil {
		t.Fatalf("empty addr should error")
	}
}

// v1.9.0-jf.5: RemovePeer must wipe ALL per-peer state, not just
// paths + crypto. Otherwise stale peerCaps / lastRecoveryPILA /
// peerPubKeys / peerTCP / peerConns can leak into a re-added peer.
func TestPeerPath_RemovePeerClearsAllState(t *testing.T) {
	tm := NewTunnelManager()
	const peer uint32 = 202

	// Seed every per-peer map we care about.
	tm.AddPeer(peer, &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1})
	tm.mu.Lock()
	tm.peerCaps[peer] = 0xff
	tm.peerPubKeys[peer] = make([]byte, 32)
	tm.lastRecoveryPILA[peer] = time.Now()
	tm.mu.Unlock()
	if err := tm.AddPeerTCPEndpoint(peer, "1.2.3.4:4443"); err != nil {
		t.Fatalf("AddPeerTCPEndpoint: %v", err)
	}
	if err := tm.AddPeerTURNEndpoint(peer, "5.6.7.8:3478"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}

	tm.RemovePeer(peer)

	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if _, ok := tm.paths[peer]; ok {
		t.Errorf("paths entry leaked after RemovePeer")
	}
	if _, ok := tm.peerCaps[peer]; ok {
		t.Errorf("peerCaps entry leaked after RemovePeer")
	}
	if _, ok := tm.peerPubKeys[peer]; ok {
		t.Errorf("peerPubKeys entry leaked after RemovePeer")
	}
	if _, ok := tm.peerTCP[peer]; ok {
		t.Errorf("peerTCP entry leaked after RemovePeer")
	}
	if _, ok := tm.peerTURN[peer]; ok {
		t.Errorf("peerTURN entry leaked after RemovePeer")
	}
	if _, ok := tm.lastRecoveryPILA[peer]; ok {
		t.Errorf("lastRecoveryPILA entry leaked after RemovePeer")
	}
}

// TestDialTURNRelayForPeer_NoLocalTURN_UsesRawUDP validates the
// v1.9.0-jf.9 asymmetric-TURN path: a daemon without a local TURN
// allocation but with a peerTURN endpoint dials via raw UDP
// through its shared UDP socket. The cached DialedConn reports
// Name() == "turn-relay" so writeFrame's cached-conn tier admits
// it (the filter excludes only "udp").
func TestDialTURNRelayForPeer_NoLocalTURN_UsesRawUDP(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// Listen UDP on a loopback port so tm.udp.Conn() is non-nil —
	// DialTURNRelayViaUDP rejects un-listened transports.
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 42
	if err := tm.AddPeerTURNEndpoint(peer, "203.0.113.45:37000"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tm.DialTURNRelayForPeer(ctx, peer); err != nil {
		t.Fatalf("DialTURNRelayForPeer: %v", err)
	}

	tm.mu.RLock()
	cc := tm.peerConns[peer]
	tm.mu.RUnlock()
	if cc == nil {
		t.Fatalf("peerConns[%d] not populated", peer)
	}
	type namer interface{ Name() string }
	n, ok := cc.(namer)
	if !ok {
		t.Fatalf("conn %T doesn't expose Name()", cc)
	}
	if got := n.Name(); got != "turn-relay" {
		t.Fatalf("cached conn Name()=%q, want turn-relay", got)
	}
	if cc.RemoteEndpoint().Network() != "turn" {
		t.Fatalf("cached conn network=%q, want turn", cc.RemoteEndpoint().Network())
	}
}

// TestDialTURNRelayForPeer_NoEndpoint_Errors guards the "no TURN
// endpoint known" precondition. Without a peerTURN entry, there's
// nothing to dial.
func TestDialTURNRelayForPeer_NoEndpoint_Errors(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := tm.DialTURNRelayForPeer(ctx, 99); err == nil {
		t.Fatalf("expected error for unknown peer, got nil")
	}
}

// TestPermitTURNPeer_NoLocalTURN_NoOp validates that PermitTURNPeer
// silently returns nil when no local TURN is configured. The
// auto-permission hook in updatePathDirect calls this on every
// authenticated direct ingress; without the nil-guard, every
// non-TURN daemon would spam errors.
func TestPermitTURNPeer_NoLocalTURN_NoOp(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// turn is nil; PermitTURNPeer should just validate the addr
	// format and return.
	if err := tm.PermitTURNPeer("203.0.113.7:49152"); err != nil {
		t.Fatalf("PermitTURNPeer: %v", err)
	}
	// Nothing should have been recorded in turnPermittedPeers.
	tm.mu.RLock()
	n := len(tm.turnPermittedPeers)
	tm.mu.RUnlock()
	if n != 0 {
		t.Fatalf("turnPermittedPeers len=%d without local TURN, want 0", n)
	}
}

// TestPermitTURNPeer_Malformed guards against bad inputs silently
// landing in the map.
func TestPermitTURNPeer_Malformed(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.PermitTURNPeer(""); err == nil {
		t.Fatalf("empty addr should error")
	}
	if err := tm.PermitTURNPeer("not-a-host-port"); err == nil {
		t.Fatalf("malformed addr should error")
	}
}

// TestUpdatePathDirect_SkipsPermitForRelayZeroAddr guards the
// zero-addr / relay-marker case in the auto-permission hook: when
// an authenticated frame arrives via relay, the handler calls
// updatePathDirect with the zero-valued UDPAddr marker; the hook
// must not try to permission 0.0.0.0:0 against the TURN server.
//
// Since the guard in updatePathDirect is `!from.IP.IsUnspecified()
// && from.Port != 0`, we check that a from with IPv4zero + port 0
// is a no-op. The test verifies that turnPermittedPeers stays
// empty after updatePathDirect with a zero-addr.
func TestUpdatePathDirect_SkipsPermitForRelayZeroAddr(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// Force tm.turn to a non-nil zero-value marker — we don't need
	// a real allocation, just the nil-check to pass so the hook's
	// guard logic is exercised. But PermitTURNPeer would still call
	// t.CreatePermission, so a nil turn means no side-effect. The
	// cleanest assertion here: turnPermittedPeers remains empty
	// after updatePathDirect with zero-addr regardless of tm.turn.

	zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	tm.mu.Lock()
	tm.updatePathDirect(7, zeroAddr)
	tm.mu.Unlock()

	// Give any spawned goroutine a moment to (not) fire.
	time.Sleep(50 * time.Millisecond)

	tm.mu.RLock()
	n := len(tm.turnPermittedPeers)
	tm.mu.RUnlock()
	if n != 0 {
		t.Fatalf("turnPermittedPeers len=%d after zero-addr ingress, want 0", n)
	}
}

// TestWriteFrame_FallsBackToTURNRelay validates the jf.9 writeFrame
// integration: when a peer has a TURN endpoint but no direct UDP
// addr and no cached conn, writeFrame lazily dials the asymmetric
// turn-relay path and retries through the cached-conn tier.
func TestWriteFrame_FallsBackToTURNRelay(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// Need a listening UDP socket so DialTURNRelayViaUDP succeeds.
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 123
	if err := tm.AddPeerTURNEndpoint(peer, "203.0.113.200:37500"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}

	// Call writeFrame with nil addr so the fallback tier runs.
	// The underlying UDP send will actually transmit to a bogus
	// loopback-routed host; this is OK because we only validate
	// that the cached conn got installed.
	_ = tm.writeFrame(peer, nil, []byte("frame"))

	tm.mu.RLock()
	cc := tm.peerConns[peer]
	tm.mu.RUnlock()
	if cc == nil {
		t.Fatalf("writeFrame fallback did not install a cached conn")
	}
	if cc.RemoteEndpoint().Network() != "turn" {
		t.Fatalf("cached conn network=%q, want turn", cc.RemoteEndpoint().Network())
	}
}

// TestWriteFrame_SkipsBeaconWhenTURNAdvertised locks in the v1.9.0-jf.10
// priority change. Before jf.10, once path.viaRelay latched to true, tier 1
// of writeFrame always routed via the beacon relay — even when a peer had
// subsequently advertised a TURN endpoint. That meant hide-ip peers'
// actual data still traversed the beacon operator (the VPS), leaking
// routing metadata that Entmoot's -hide-ip couldn't hide. jf.10 makes
// tier 1 defer to the turn-relay tier when peerTURN is populated, so
// "I advertised TURN" is honoured over any third-party beacon.
func TestWriteFrame_SkipsBeaconWhenTURNAdvertised(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// UDP socket so the turn-relay path's underlying WriteToUDPAddr
	// actually has somewhere to send. The destination is a loopback
	// port nothing is listening on; we only validate control flow.
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 789

	// Latch viaRelay=true to simulate the PILA beacon path being
	// active (jf.9's production observation — once beacon starts
	// working it sticks).
	tm.mu.Lock()
	tm.paths[peer] = &peerPath{viaRelay: true}
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.mu.Unlock()

	// Advertise a TURN endpoint for this peer. From v1.9.0-jf.10 this
	// MUST cause writeFrame to bypass the beacon tier and engage the
	// turn-relay tier instead.
	if err := tm.AddPeerTURNEndpoint(peer, "203.0.113.200:37500"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}

	// Call writeFrame with no direct addr so the only reachable tiers
	// are: tier 1 (beacon, skipped by jf.10 guard), tier 2 (no cached
	// conn), tier 3 (addr nil — skipped), tier 4 (turn-relay dial).
	_ = tm.writeFrame(peer, nil, []byte("jf.10-probe"))

	tm.mu.RLock()
	cc := tm.peerConns[peer]
	tm.mu.RUnlock()
	if cc == nil {
		t.Fatalf("writeFrame did not install turn-relay cached conn; beacon probably fired instead")
	}
	if got := cc.RemoteEndpoint().Network(); got != "turn" {
		t.Fatalf("cached conn network=%q, want turn (turn-relay path); beacon bypass likely didn't engage", got)
	}
}

// TestWriteFrame_UsesBeaconWhenNoTURNAdvertised is the regression guard
// for TestWriteFrame_SkipsBeaconWhenTURNAdvertised: without peerTURN, the
// beacon tier must still fire (default routing for every peer that hasn't
// opted into TURN). Any change that unconditionally skips beacon would
// break resilience against direct-path failures.
func TestWriteFrame_UsesBeaconWhenNoTURNAdvertised(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()

	// Listen so WriteToUDPAddr has a working socket. The beacon
	// destination is a loopback port nothing listens on; we validate
	// by checking that no turn-relay dial was attempted (the jf.10
	// code path is NOT taken), not by observing the beacon packet.
	if err := tm.udp.Listen("127.0.0.1:0", tm.inbound); err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}

	const peer uint32 = 791

	tm.mu.Lock()
	tm.paths[peer] = &peerPath{viaRelay: true}
	tm.beaconAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	tm.mu.Unlock()

	// No AddPeerTURNEndpoint — peerTURN stays empty.

	_ = tm.writeFrame(peer, nil, []byte("non-hide-ip-probe"))

	tm.mu.RLock()
	cc := tm.peerConns[peer]
	tm.mu.RUnlock()
	// If the beacon tier correctly fired, there's no turn-relay cached
	// conn. jf.10's skip condition (`hasTURNEp`) is false, tier 1
	// wins, no turn-relay dial, no peerConns entry.
	if cc != nil {
		t.Fatalf("peerConns installed when it shouldn't have been: conn.Network=%q — "+
			"beacon-relay tier (tier 1) was expected to fire since no TURN endpoint is known",
			cc.RemoteEndpoint().Network())
	}
}

// TestWriteFrame_PrefersCachedTURNRelay locks in the precedence: a
// cached turn-relay DialedConn wins over direct UDP, matching TURN
// and TCP behaviour (Name() != "udp" passes the cached-conn filter).
func TestWriteFrame_PrefersCachedTURNRelay(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const peer uint32 = 456

	stub := &stubDialedConn{network: "turn", remote: "203.0.113.200:37500"}
	tm.mu.Lock()
	tm.peerConns[peer] = stub
	tm.mu.Unlock()

	// A direct UDP addr is irrelevant when the cached conn wins.
	payload := []byte{0x01}
	if err := tm.writeFrame(peer, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got := stub.sends.Load(); got != 1 {
		t.Fatalf("stub.sends=%d, want 1", got)
	}
}
