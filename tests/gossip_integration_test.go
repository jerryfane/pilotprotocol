package tests

import (
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/gossip"
)

// TestGossipPropagatesAcrossLineGraph exercises the additive
// peer-discovery layer end-to-end: four daemons in a 1↔2↔3↔4
// topology, each of which only forms an encrypted tunnel with its
// direct neighbor, still converge on a full membership view after a
// few gossip rounds. The key assertion is that node 1 learns about
// node 4 without ever issuing a registry resolve for node 4 — this
// is what gossip gets us over a registry-only world.
func TestGossipPropagatesAcrossLineGraph(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Short tick so the test doesn't need to wait 25s for
	// production cadence. 100ms is tight enough for fast convergence
	// and loose enough that the tickers don't collapse into a
	// single monotonic loop on slow CI.
	fastGossip := func(c *daemon.Config) {
		c.GossipInterval = 100 * time.Millisecond
		c.Encrypt = true
	}
	infoA := env.AddDaemon(fastGossip)
	infoB := env.AddDaemon(fastGossip)
	infoC := env.AddDaemon(fastGossip)
	infoD := env.AddDaemon(fastGossip)

	a, b, c, d := infoA.Daemon, infoB.Daemon, infoC.Daemon, infoD.Daemon
	t.Logf("line graph: A=%d B=%d C=%d D=%d", a.NodeID(), b.NodeID(), c.NodeID(), d.NodeID())

	// Establish neighbor tunnels by dialing port 7 (echo) — triggers
	// handshake + encrypted-tunnel setup. Each pair becomes a
	// gossip-capable edge; non-neighbors never exchange a tunnel
	// (and, in particular, never call ensureTunnel on each other).
	mustEchoReach := func(from, to *DaemonInfo) {
		t.Helper()
		conn, err := from.Driver.Dial(to.Daemon.Addr().String() + ":7")
		if err != nil {
			t.Fatalf("dial %d→%d: %v", from.Daemon.NodeID(), to.Daemon.NodeID(), err)
		}
		// The echo service on port 7 is connectionless (ProtoDatagram),
		// but dialing it opens a stream for subsequent writes. We
		// only need the stream established, not the payload.
		conn.Close()
	}
	mustEchoReach(infoA, infoB) // A—B edge
	mustEchoReach(infoB, infoC) // B—C edge
	mustEchoReach(infoC, infoD) // C—D edge

	// Wait for each edge's encrypted tunnel to come up so caps are
	// exchanged. Absent this the tick-loop skips all peers because
	// they aren't marked ready.
	waitForEncryptedPeers(t, a, 1)
	waitForEncryptedPeers(t, b, 2) // B is a middle node
	waitForEncryptedPeers(t, c, 2)
	waitForEncryptedPeers(t, d, 1)

	// Now each daemon's view is prime: it contains its direct
	// neighbor(s) from ensureTunnel's registry resolve. Critically,
	// node 1 has NOT resolved node 4. Verify that baseline so the
	// convergence assertion below actually means something.
	if _, _, ok := a.GossipView().Get(d.NodeID()); ok {
		t.Fatalf("pre-gossip: A's view already contains D — test premise broken")
	}

	// Nudge the ticker along deterministically. Three synchronized
	// tick cycles across the line are enough for node 4's record to
	// propagate all the way to node 1 (one hop per tick).
	for i := 0; i < 5; i++ {
		a.TriggerGossipTick()
		b.TriggerGossipTick()
		c.TriggerGossipTick()
		d.TriggerGossipTick()
		// memTransport in unit tests is synchronous; the real
		// transport hops through ProtoControl packets which are
		// processed on a goroutine. Give the dispatcher a chance
		// to land each round.
		time.Sleep(50 * time.Millisecond)
	}

	// Either the forced ticks succeeded or the background ticker
	// will have done it by now. Poll for up to 3s as safety.
	deadline := time.Now().Add(3 * time.Second)
	var found bool
	var record gossip.GossipRecord
	for time.Now().Before(deadline) {
		if rec, _, ok := a.GossipView().Get(d.NodeID()); ok {
			found = true
			record = rec
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		// Diagnostic dump of final state.
		for _, di := range []*DaemonInfo{infoA, infoB, infoC, infoD} {
			view := di.Daemon.GossipView()
			ids := []uint32{}
			srcs := []gossip.Source{}
			for _, probe := range []uint32{a.NodeID(), b.NodeID(), c.NodeID(), d.NodeID()} {
				if _, src, ok := view.Get(probe); ok {
					ids = append(ids, probe)
					srcs = append(srcs, src)
				}
			}
			t.Logf("post-tick daemon %d: view=%v sources=%v", di.Daemon.NodeID(), ids, srcs)
		}
		t.Fatalf("A's view never learned about D via gossip")
	}

	// The record must be signed by D — SourceGossip means we
	// verified an Ed25519 signature under D's pinned key.
	_, src, _ := a.GossipView().Get(d.NodeID())
	if src != gossip.SourceGossip {
		t.Errorf("expected SourceGossip on A's D entry, got %v", src)
	}
	if record.NodeID != d.NodeID() {
		t.Errorf("wrong node_id in gossiped record: %d", record.NodeID)
	}
	t.Logf("A learned D=%d via gossip: addr=%s hostname=%q", record.NodeID, record.RealAddr, record.Hostname)
}

// TestGossipSkipsStockDaemons verifies that a daemon lacking the
// gossip capability stays invisible to the engine's tick-target
// selector — i.e. the engine never sends gossip frames to peers
// who didn't advertise CapGossip in their PILA trailer. Models the
// mixed-version deployment scenario: upgraded daemons coexist with
// stock v1.7.2 ones and simply exclude them from the overlay.
func TestGossipSkipsStockDaemons(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoNew := env.AddDaemon(func(c *daemon.Config) {
		c.GossipInterval = 100 * time.Millisecond
		c.Encrypt = true
	})
	// "Stock" daemon: gossip engine starts (we can't easily disable
	// it from config), but simulate an older daemon by zeroing out
	// its local-advertised caps right after startup so it doesn't
	// advertise CapGossip on its outbound PILA frames.
	infoStock := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
	})
	stockTunnels := infoStock.Daemon.Tunnels()
	stockTunnels.SetLocalCaps(0) // revert to "I don't speak gossip"

	// Ensure the encrypted tunnel is up and caps are exchanged.
	if _, err := infoNew.Driver.Dial(infoStock.Daemon.Addr().String() + ":7"); err != nil {
		t.Fatalf("new→stock dial: %v", err)
	}
	waitForEncryptedPeers(t, infoNew.Daemon, 1)

	// The stock daemon advertised caps=0, so infoNew's view of it
	// must NOT include CapGossip.
	caps := infoNew.Daemon.Tunnels().PeerCaps(infoStock.Daemon.NodeID())
	if gossip.HasCap(caps, gossip.CapGossip) {
		t.Errorf("expected stock peer caps=0 for CapGossip bit; got caps=%#b", caps)
	}
	// And the engine's selector must refuse to pick it.
	capable := infoNew.Daemon.Tunnels().GossipCapablePeers()
	for _, id := range capable {
		if id == infoStock.Daemon.NodeID() {
			t.Errorf("stock peer %d leaked into gossip-capable selector", id)
		}
	}
	t.Logf("stock peer correctly excluded from gossip (%d capable peers)", len(capable))
}

// waitForEncryptedPeers polls daemon.Info() until EncryptedPeers
// reaches the expected count. Fails the test on timeout; the
// existing tunnel_encrypt_test uses the same pattern.
func waitForEncryptedPeers(t *testing.T, d *daemon.Daemon, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info := d.Info()
		if int(info.EncryptedPeers) >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon %d: timeout waiting for %d encrypted peers (have %d)", d.NodeID(), want, info.EncryptedPeers)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
