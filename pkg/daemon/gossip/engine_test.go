package gossip

import (
	"crypto/ed25519"
	"encoding/json"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// memTransport routes frames between engines in-process for tests.
// Thread-safe; each direction is serialized through the receiving
// engine's OnInbound.
type memTransport struct {
	mu        sync.Mutex
	selfNode  uint32
	targets   map[uint32]*Engine // peer_node_id → their engine
	tracePeer uint32             // set during Send to identify sender; unused by engine but handy in tests
}

func newMemTransport(selfNode uint32) *memTransport {
	return &memTransport{selfNode: selfNode, targets: make(map[uint32]*Engine)}
}

func (m *memTransport) SendGossipFrame(dstNode uint32, payload []byte) error {
	m.mu.Lock()
	peer, ok := m.targets[dstNode]
	m.mu.Unlock()
	if !ok {
		return nil // dropped: test decides what's reachable
	}
	peer.OnInbound(m.selfNode, payload)
	return nil
}

// connect wires m's selfNode into peerEngine's transport and vice
// versa so frames flow bidirectionally.
func (m *memTransport) connect(selfEngine *Engine, peerNode uint32, peerEngine *Engine, peerTransport *memTransport) {
	m.mu.Lock()
	m.targets[peerNode] = peerEngine
	m.mu.Unlock()
	peerTransport.mu.Lock()
	peerTransport.targets[m.selfNode] = selfEngine
	peerTransport.mu.Unlock()
}

// staticPeers implements PeerSource with a fixed list.
type staticPeers struct{ ids []uint32 }

func (s staticPeers) GossipCapablePeers() []uint32 { return append([]uint32(nil), s.ids...) }

// keyMap implements KeyLookup from a map.
type keyMap map[uint32]ed25519.PublicKey

func (k keyMap) lookup(id uint32) (ed25519.PublicKey, bool) {
	pk, ok := k[id]
	return pk, ok
}

// fixtureEngine builds a test Engine with a deterministic rng seed
// so peer picks are reproducible.
func fixtureEngine(t *testing.T, nodeID uint32, peers []uint32, trans Transport) (*Engine, *crypto.Identity, *MembershipView) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	view := NewMembershipView()
	self := func() *GossipRecord {
		return &GossipRecord{
			NodeID:   nodeID,
			RealAddr: "127.0.0.1:1000",
			Endpoints: []registry.NodeEndpoint{
				{Network: "tcp", Addr: "127.0.0.1:4443"},
			},
			Hostname: "test",
		}
	}
	keys := make(keyMap)
	e := NewEngine(id, view, trans, staticPeers{peers}, self, keys.lookup, 50*time.Millisecond)
	e.rng = rand.New(rand.NewSource(int64(nodeID)))
	return e, id, view
}

// TestTickConvergesTwoEngines: two engines, each with its own
// self-record, share tunnels via memTransport. After a single tick
// each the two views both contain both nodes.
func TestTickConvergesTwoEngines(t *testing.T) {
	tA := newMemTransport(1)
	tB := newMemTransport(2)

	eA, _, viewA := fixtureEngine(t, 1, []uint32{2}, tA)
	eB, _, viewB := fixtureEngine(t, 2, []uint32{1}, tB)

	tA.connect(eA, 2, eB, tB)

	// Engine A ticks first — sends sync to B (which has nothing).
	eA.Tick()
	// B now has A's digests (1 entry: node 1). B's response: send A
	// records A doesn't have. Since B has just its own record from
	// refreshSelf (inside handleSync → handleDelta round), we drive
	// that now by making B tick. Actually handleSync runs inline in
	// the call above because memTransport is synchronous — so at
	// this point A's view already has A, and B's view has B (from
	// its own refreshSelf during handleSync? No: handleSync doesn't
	// call refreshSelf; only Tick does).

	// Run B.Tick so B refreshes its own record then sends a sync to A.
	eB.Tick()

	// After these two ticks both views should contain both nodes.
	if _, _, ok := viewA.Get(2); !ok {
		t.Errorf("A's view missing node 2 after tick")
	}
	if _, _, ok := viewB.Get(1); !ok {
		t.Errorf("B's view missing node 1 after tick")
	}

	// Each side must have accepted the other as SourceGossip
	// (remote-signed); own records are SourceLocal.
	if _, src, _ := viewA.Get(2); src != SourceGossip {
		t.Errorf("A's entry for 2 should be SourceGossip, got %v", src)
	}
	if _, src, _ := viewB.Get(1); src != SourceGossip {
		t.Errorf("B's entry for 1 should be SourceGossip, got %v", src)
	}
}

// TestInboundDeltaRejectsBadSignature: a forged record is dropped
// without updating the view.
func TestInboundDeltaRejectsBadSignature(t *testing.T) {
	tA := newMemTransport(1)
	eA, _, viewA := fixtureEngine(t, 1, []uint32{}, tA)

	// Craft a record from another identity, then tamper with the
	// RealAddr so the signature no longer verifies.
	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	bad := &GossipRecord{NodeID: 99, RealAddr: "1.2.3.4:5", LastSeen: 100}
	if err := Sign(bad, other); err != nil {
		t.Fatalf("sign: %v", err)
	}
	bad.RealAddr = "9.9.9.9:9"

	if err := eA.acceptRecord(bad, 42); err == nil {
		t.Errorf("expected acceptRecord to reject tampered record")
	}
	if _, _, ok := viewA.Get(99); ok {
		t.Errorf("tampered record leaked into view")
	}
}

// TestInboundDeltaRejectsMismatchedPinnedKey: if the engine has a
// pinned key for this nodeID (e.g. from the registry) and the record
// claims a different key, reject.
func TestInboundDeltaRejectsMismatchedPinnedKey(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	imposter, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("imposter identity: %v", err)
	}
	view := NewMembershipView()

	// KeyLookup pins imposter claims to id's true key. Any record
	// signed by imposter for that id must be rejected.
	keys := keyMap{99: id.PublicKey}

	e := NewEngine(id, view, newMemTransport(1), staticPeers{}, nil, keys.lookup, 50*time.Millisecond)

	bad := &GossipRecord{NodeID: 99, RealAddr: "1.2.3.4:5", LastSeen: 100}
	if err := Sign(bad, imposter); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := e.acceptRecord(bad, 42); err == nil {
		t.Errorf("expected rejection on pinned-key mismatch")
	}
}

// TestTickNoOpWithNoCapablePeers: an engine with no gossip-capable
// peers should tick silently without calling the transport.
func TestTickNoOpWithNoCapablePeers(t *testing.T) {
	tr := &countingTransport{}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	view := NewMembershipView()
	self := func() *GossipRecord {
		return &GossipRecord{NodeID: 1, RealAddr: "1.2.3.4:5"}
	}
	e := NewEngine(id, view, tr, staticPeers{}, self, nil, 50*time.Millisecond)
	e.Tick()
	if tr.sends != 0 {
		t.Errorf("expected no transport calls; got %d", tr.sends)
	}
}

// TestOpportunisticPushSendsPropagatableRecords: PushTo(peer) emits
// a delta containing propagatable records, and omits
// registry-sourced ones.
func TestOpportunisticPushSendsPropagatableRecords(t *testing.T) {
	tr := &countingTransport{}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	view := NewMembershipView()
	self := func() *GossipRecord {
		return &GossipRecord{NodeID: 1, RealAddr: "1.2.3.4:5"}
	}
	e := NewEngine(id, view, tr, staticPeers{}, self, nil, 50*time.Millisecond)

	// Seed view with a SourceGossip entry (propagatable) and a
	// SourceRegistry entry (not propagatable).
	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("other id: %v", err)
	}
	ok := &GossipRecord{NodeID: 7, RealAddr: "7.7.7.7:7", LastSeen: 100}
	if err := Sign(ok, other); err != nil {
		t.Fatalf("sign: %v", err)
	}
	view.Put(ok, SourceGossip, 0)
	view.ReplaceFromRegistry(&GossipRecord{NodeID: 8, RealAddr: "8.8.8.8:8", LastSeen: 100, PublicKey: other.PublicKey})

	e.refreshSelf() // so SourceLocal record exists
	e.PushTo(42)

	if tr.sends != 1 {
		t.Fatalf("expected one push; got %d", tr.sends)
	}
	delta, err := UnmarshalDelta(tr.lastPayload)
	// Actually the payload is a Frame wrapper, not a raw GossipDelta.
	if err == nil && delta != nil && len(delta.Records) > 0 {
		// Not the expected shape; ignore.
		_ = delta
	}
	frame := Frame{}
	if err := unmarshalFrame(tr.lastPayload, &frame); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if frame.Type != frameTypeDelta {
		t.Fatalf("expected delta frame, got %q", frame.Type)
	}
	nodes := map[uint32]bool{}
	for _, r := range frame.Records {
		nodes[r.NodeID] = true
	}
	if !nodes[1] {
		t.Errorf("missing self (SourceLocal) in push")
	}
	if !nodes[7] {
		t.Errorf("missing SourceGossip entry in push")
	}
	if nodes[8] {
		t.Errorf("SourceRegistry entry leaked into push")
	}
}

// TestStartStop smoke-tests the background tick goroutine.
func TestStartStop(t *testing.T) {
	tr := &countingTransport{}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	view := NewMembershipView()
	self := func() *GossipRecord { return &GossipRecord{NodeID: 1, RealAddr: "1.2.3.4:5"} }

	e := NewEngine(id, view, tr, staticPeers{}, self, nil, 100*time.Millisecond)
	e.Start()
	e.Start() // idempotent
	time.Sleep(50 * time.Millisecond)
	e.Stop()
	e.Stop() // idempotent
}

// countingTransport is a Transport implementation that records how
// many frames were sent and keeps the last payload for inspection.
type countingTransport struct {
	mu          sync.Mutex
	sends       int
	lastPayload []byte
}

func (t *countingTransport) SendGossipFrame(dstNode uint32, payload []byte) error {
	t.mu.Lock()
	t.sends++
	t.lastPayload = append([]byte(nil), payload...)
	t.mu.Unlock()
	return nil
}

// unmarshalFrame is a tiny shim around json.Unmarshal purely so the
// test body reads as "frame operation" rather than "json dance".
func unmarshalFrame(data []byte, f *Frame) error {
	return json.Unmarshal(data, f)
}
