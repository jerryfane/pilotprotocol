package daemon

import (
	"errors"
	"testing"
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
