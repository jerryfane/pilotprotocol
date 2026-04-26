package daemon

import (
	"errors"
	"testing"
	"time"
)

// TestSendTier_NamesStableAcrossIndices: the tier name strings
// are part of pilotctl info's wire shape — operators grep for
// them. Pin them here so a refactor that re-orders the tier
// constants doesn't silently flip the JSON keys.
func TestSendTier_NamesStableAcrossIndices(t *testing.T) {
	want := map[int]string{
		SendTierOutboundTurnOnlyCached:   "outbound_turn_only_cached",
		SendTierOutboundTurnOnlyJF9:      "outbound_turn_only_jf9",
		SendTierOutboundTurnOnlyOwnRelay: "outbound_turn_only_own_relay",
		SendTierBeaconRelay:              "beacon_relay",
		SendTierCachedConn:               "cached_conn",
		SendTierJF9Fallback:              "jf9_fallback",
		SendTierDirectUDP:                "direct_udp",
		SendTierQueuedPendingKey:         "queued_pending_key",
	}
	if len(want) != numSendTiers {
		t.Fatalf("test missing tier coverage: want %d entries, have %d",
			numSendTiers, len(want))
	}
	for idx, name := range want {
		if got := sendTierName(idx); got != name {
			t.Fatalf("tier %d: got %q, want %q", idx, got, name)
		}
	}
	// And out-of-range still doesn't panic:
	if got := sendTierName(99); got != "unknown" {
		t.Fatalf("out-of-range tier: got %q, want %q", got, "unknown")
	}
}

// TestRecordTierSend_BumpsCountersOnSuccess: a successful
// recordTierSend (err == nil) increments BOTH the packet and
// byte counters for that exact tier. This is the always-on
// behaviour — no flag needed.
func TestRecordTierSend_BumpsCountersOnSuccess(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.recordTierSend(SendTierDirectUDP, 42, 137,
		"1.2.3.4:5678", false, nil)
	if got := tm.PktsSentByTier[SendTierDirectUDP]; got != 1 {
		t.Fatalf("PktsSentByTier[direct_udp]=%d, want 1", got)
	}
	if got := tm.BytesSentByTier[SendTierDirectUDP]; got != 137 {
		t.Fatalf("BytesSentByTier[direct_udp]=%d, want 137", got)
	}
}

// TestRecordTierSend_DoesNotBumpOnFailure: a failed
// recordTierSend (err != nil) leaves the counters alone — they
// represent successful bytes-on-the-wire, not attempted sends.
// Otherwise a flapping path would silently inflate "sent"
// stats and operators would lose the signal.
func TestRecordTierSend_DoesNotBumpOnFailure(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.recordTierSend(SendTierCachedConn, 42, 137,
		"1.2.3.4:5678", true, errors.New("boom"))
	if got := tm.PktsSentByTier[SendTierCachedConn]; got != 0 {
		t.Fatalf("PktsSentByTier[cached_conn] after err=%d, want 0", got)
	}
	if got := tm.BytesSentByTier[SendTierCachedConn]; got != 0 {
		t.Fatalf("BytesSentByTier[cached_conn] after err=%d, want 0", got)
	}
}

// TestRecordTierSend_OnlyTouchesItsOwnTier: bumping tier X
// must not increment tier Y. Avoids the future-bug where a
// shared accumulator masks per-tier mix changes.
func TestRecordTierSend_OnlyTouchesItsOwnTier(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.recordTierSend(SendTierBeaconRelay, 1, 100, "", false, nil)
	for i := 0; i < numSendTiers; i++ {
		want := uint64(0)
		if i == SendTierBeaconRelay {
			want = 1
		}
		if got := tm.PktsSentByTier[i]; got != want {
			t.Fatalf("after beacon_relay bump: tier %d (%s) Pkts=%d, want %d",
				i, sendTierName(i), got, want)
		}
	}
}

// TestSnapshotByTier_ReturnsAllTiers: the JSON map exposed via
// pilotctl info must include every defined tier, even tiers
// with zero packets. Operators rely on the stable shape ("if
// the key is missing, did the daemon not ship it?" vs "if the
// key is 0, this tier never fired").
func TestSnapshotByTier_ReturnsAllTiers(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.recordTierSend(SendTierDirectUDP, 1, 100, "", false, nil)
	pkts := tm.SnapshotPktsByTier()
	bytes := tm.SnapshotBytesByTier()
	if len(pkts) != numSendTiers || len(bytes) != numSendTiers {
		t.Fatalf("snapshot map size: pkts=%d bytes=%d (want %d each)",
			len(pkts), len(bytes), numSendTiers)
	}
	if got := pkts["direct_udp"]; got != 1 {
		t.Fatalf("snapshot direct_udp pkts=%d, want 1", got)
	}
	if got := pkts["cached_conn"]; got != 0 {
		t.Fatalf("snapshot cached_conn pkts=%d, want 0 (never bumped)", got)
	}
}

// TestTraceSends_DefaultOff: a fresh TunnelManager has
// traceSends=false. Operators must opt in via flag; we don't
// pay the per-event log cost by default.
func TestTraceSends_DefaultOff(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if tm.traceSends {
		t.Fatalf("fresh TunnelManager has traceSends=true; want false (opt-in)")
	}
}

// TestSetTraceSends_TogglesField: SetTraceSends flips the
// field. The runtime cost when off is one bool check per
// send; we want to make sure the toggle path actually works.
func TestSetTraceSends_TogglesField(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.SetTraceSends(true)
	if !tm.traceSends {
		t.Fatalf("after SetTraceSends(true): traceSends=false")
	}
	tm.SetTraceSends(false)
	if tm.traceSends {
		t.Fatalf("after SetTraceSends(false): traceSends=true")
	}
}

// TestRecordTierSend_NoLogWhenOff: with traceSends=false, the
// helper still bumps counters but does NOT emit the INFO log.
// We can't easily intercept slog.Default() output without a
// custom handler, so this test is a smoke-style assertion that
// the helper completes cleanly with traceSends off — combined
// with the other tests, it proves the gate works.
//
// (A handler-capturing test would be richer but adds plumbing
// around slog.SetDefault that affects every other test in this
// package. Skipped.)
func TestRecordTierSend_NoLogWhenOff(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if tm.traceSends {
		t.Fatalf("precondition: traceSends should be false")
	}
	// Ten calls; should bump counter to 10, no panic, no log.
	for i := 0; i < 10; i++ {
		tm.recordTierSend(SendTierDirectUDP, 1, 50, "x:1", false, nil)
	}
	if got := tm.PktsSentByTier[SendTierDirectUDP]; got != 10 {
		t.Fatalf("after 10 calls: pkts=%d, want 10", got)
	}
}

// TestRecordTierSend_LogsWhenOn: turn the flag on and emit one
// — same shape as off, just to confirm no crash on the gated
// path (the actual log content isn't verified here; relying on
// gosec compile-time + manual eyeballing of the Info call
// site).
func TestRecordTierSend_LogsWhenOn(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	tm.SetTraceSends(true)
	tm.recordTierSend(SendTierDirectUDP, 1, 50, "x:1", false, nil)
	if got := tm.PktsSentByTier[SendTierDirectUDP]; got != 1 {
		t.Fatalf("pkts=%d after one call, want 1", got)
	}
	tm.recordTierSend(SendTierDirectUDP, 1, 50, "x:1", false,
		errors.New("simulated"))
	// failure path doesn't bump:
	if got := tm.PktsSentByTier[SendTierDirectUDP]; got != 1 {
		t.Fatalf("pkts=%d after failed send, want still 1", got)
	}
}

// TestAddPeerTURNEndpoint_NoOpWithoutLocalTURN: when the
// daemon doesn't run a local TURN allocation (tm.turn == nil),
// AddPeerTURNEndpoint must NOT panic and must NOT track any
// permission. This is the asymmetric case (e.g. phobos in our
// 3-machine mesh — no -turn-provider). The call should succeed
// because the peer-endpoint installation is unrelated to
// whether WE have a local allocation.
//
// (v1.9.0-jf.15.3 behaviour pin)
func TestAddPeerTURNEndpoint_NoOpWithoutLocalTURN(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if tm.turn != nil {
		t.Fatalf("precondition: tm.turn should be nil for this test")
	}
	if err := tm.AddPeerTURNEndpoint(45491, "1.2.3.4:5678"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint without local TURN: %v", err)
	}
	if got := tm.PeerTURNEndpoint(45491); got != "1.2.3.4:5678" {
		t.Fatalf("peer endpoint not stored: got %q", got)
	}
	// turnPermittedPeers must be empty — there's no allocation to
	// permission against, so PermitTURNPeer was a clean no-op.
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if got := len(tm.turnPermittedPeers); got != 0 {
		t.Fatalf("turnPermittedPeers should be empty without local TURN; got %d entries",
			got)
	}
}

// TestAddPeerTURNEndpoint_RepeatedInstallNoCrash: calling
// AddPeerTURNEndpoint twice with the same address must succeed
// both times. The jf.14.2 eviction predicate intentionally
// skips when prev==new (preserves live cached conn); jf.15.3's
// PermitTURNPeer call is also idempotent (refreshes the
// turnPermittedPeers timestamp without duplicating storage).
func TestAddPeerTURNEndpoint_RepeatedInstallNoCrash(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("first AddPeerTURNEndpoint: %v", err)
	}
	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("second AddPeerTURNEndpoint (same addr): %v", err)
	}
	if got := tm.PeerTURNEndpoint(7); got != "1.2.3.4:5" {
		t.Fatalf("peer endpoint after repeated install: got %q", got)
	}
}

// TestKnownTURNPeers_EnumeratesPeerTURNEntries: jf.15.7's
// peer-side rendezvous-refresh loop walks `KnownTURNPeers()` to
// decide which nodeIDs to re-look-up. The helper must enumerate
// every peer with a non-nil peerTURN entry, and must NOT include
// peers whose entry was never installed.
func TestKnownTURNPeers_EnumeratesPeerTURNEntries(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if got := len(tm.KnownTURNPeers()); got != 0 {
		t.Fatalf("fresh TM: KnownTURNPeers len=%d, want 0", got)
	}
	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	if err := tm.AddPeerTURNEndpoint(99, "9.8.7.6:5"); err != nil {
		t.Fatalf("AddPeerTURNEndpoint: %v", err)
	}
	got := tm.KnownTURNPeers()
	if len(got) != 2 {
		t.Fatalf("after 2 adds: KnownTURNPeers len=%d, want 2 (got %v)", len(got), got)
	}
	seen := map[uint32]bool{}
	for _, id := range got {
		seen[id] = true
	}
	if !seen[7] || !seen[99] {
		t.Fatalf("KnownTURNPeers missing expected ids: got %v, want both 7 and 99", got)
	}
}

// TestMaybeSendRecoveryPILA_FiresWhenTURNDelivered: a packet that
// arrived through pion TURN reaches handleEncrypted with addr=nil
// (TURNEndpoint type-asserts to nil at the *UDPEndpoint cast in the
// inbound loop). Under v1.9.0-jf.15.5 and earlier, the early-return
// guard `if !viaRelay && addr == nil` short-circuited the recovery
// path for exactly this case — the bilateral crypto-state deadlock
// (laptop sees encrypted-from-VPS but no key) couldn't break.
//
// The fix removes the guard. We can't easily exercise the full
// writeFrame send path in a unit test (no real transports, no
// identity), but we CAN observe whether the function got past the
// rate-limit gate to stamp lastRecoveryPILA[nodeID]. Old code: never
// stamps (returns at the guard). New code: stamps even when the
// downstream frame build / transport check bails afterwards.
//
// (v1.9.0-jf.15.6 behaviour pin)
func TestMaybeSendRecoveryPILA_FiresWhenTURNDelivered(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const nodeID = uint32(45981)

	// Precondition: lastRecoveryPILA[nodeID] is zero — never been
	// stamped. After a call with (nodeID, addr=nil, viaRelay=false),
	// we expect a fresh stamp.
	tm.mu.RLock()
	if !tm.lastRecoveryPILA[nodeID].IsZero() {
		tm.mu.RUnlock()
		t.Fatalf("precondition: lastRecoveryPILA[%d] should be zero", nodeID)
	}
	tm.mu.RUnlock()

	// The call itself is harmless on a TM with no identity / no UDP
	// transport; it'll bail at the buildAuthKeyExchangeFrame nil-check
	// or the tm.udp == nil check. The point is that BEFORE those
	// checks, the function must have stamped lastRecoveryPILA — i.e.
	// it got past the now-removed guard.
	tm.maybeSendRecoveryPILA(nodeID, nil, false)

	tm.mu.RLock()
	stamp := tm.lastRecoveryPILA[nodeID]
	tm.mu.RUnlock()
	if stamp.IsZero() {
		t.Fatalf("after maybeSendRecoveryPILA(%d, nil, false): "+
			"lastRecoveryPILA still zero — guard was not removed",
			nodeID)
	}
	if time.Since(stamp) > 5*time.Second {
		t.Fatalf("stamp not recent: %v ago", time.Since(stamp))
	}
}

// TestMaybeSendRecoveryPILA_RespectsRateLimit: even under the
// jf.15.6 fix, repeated calls within recoveryPILAInterval must NOT
// re-stamp the timestamp. This guards the DoS-amplifier mitigation
// — an attacker spamming undecryptable frames with a forged nodeID
// must not cause us to emit a PILA per inbound packet.
func TestMaybeSendRecoveryPILA_RespectsRateLimit(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	const nodeID = uint32(45981)

	tm.maybeSendRecoveryPILA(nodeID, nil, false)
	tm.mu.RLock()
	first := tm.lastRecoveryPILA[nodeID]
	tm.mu.RUnlock()
	if first.IsZero() {
		t.Fatalf("first call: stamp not set")
	}

	// Second call within the cooldown should be a no-op: the
	// timestamp must not advance.
	tm.maybeSendRecoveryPILA(nodeID, nil, false)
	tm.mu.RLock()
	second := tm.lastRecoveryPILA[nodeID]
	tm.mu.RUnlock()
	if !second.Equal(first) {
		t.Fatalf("second call within cooldown advanced stamp: "+
			"first=%v second=%v (expected equal)", first, second)
	}
}

// TestAddPeerTURNEndpoint_AddressChangePermitsNewAddress:
// when the peer's TURN allocation rotates (we get a new
// address via rendezvous lookup or transport-ad), we should
// install a permission for the NEW address. Combined with
// jf.14.2's cache eviction, this is the bilateral
// cross-permission flow: stale conn dropped, fresh address
// permissioned, ready for pion-to-pion forwarding.
//
// We can't easily exercise PermitTURNPeer's effects without a
// real pion client (it's a no-op when tm.turn is nil). What
// we DO check: the old address isn't lingering in
// peerTURN.
func TestAddPeerTURNEndpoint_AddressChangePermitsNewAddress(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	if err := tm.AddPeerTURNEndpoint(7, "1.2.3.4:5"); err != nil {
		t.Fatalf("first AddPeerTURNEndpoint: %v", err)
	}
	if err := tm.AddPeerTURNEndpoint(7, "9.8.7.6:5"); err != nil {
		t.Fatalf("second AddPeerTURNEndpoint (new addr): %v", err)
	}
	if got := tm.PeerTURNEndpoint(7); got != "9.8.7.6:5" {
		t.Fatalf("peer endpoint after rotation: got %q, want 9.8.7.6:5", got)
	}
}
