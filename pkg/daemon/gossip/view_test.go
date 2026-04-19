package gossip

import (
	"sync"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

func signed(t *testing.T, id *crypto.Identity, nodeID uint32, lastSeen int64) *GossipRecord {
	t.Helper()
	r := &GossipRecord{
		NodeID:    nodeID,
		RealAddr:  "1.2.3.4:37736",
		Endpoints: []registry.NodeEndpoint{{Network: "tcp", Addr: "1.2.3.4:4443"}},
		Hostname:  "host",
		LastSeen:  lastSeen,
	}
	if err := Sign(r, id); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r
}

func TestPutInsertAndGet(t *testing.T) {
	v := NewMembershipView()
	id := newIdentity(t)
	r := signed(t, id, 42, 100)

	if got := v.Put(r, SourceGossip, 7); got != MergeInserted {
		t.Fatalf("first insert result: %v", got)
	}
	rec, src, ok := v.Get(42)
	if !ok {
		t.Fatalf("Get missed")
	}
	if rec.NodeID != 42 || rec.LastSeen != 100 || src != SourceGossip {
		t.Fatalf("unexpected stored record: %+v (src %v)", rec, src)
	}
}

func TestPutNewerWinsOlderLoses(t *testing.T) {
	v := NewMembershipView()
	id := newIdentity(t)

	v.Put(signed(t, id, 1, 100), SourceGossip, 2)
	if got := v.Put(signed(t, id, 1, 99), SourceGossip, 2); got != MergeStale {
		t.Fatalf("older LastSeen should be stale, got %v", got)
	}
	if got := v.Put(signed(t, id, 1, 100), SourceGossip, 2); got != MergeStale {
		t.Fatalf("equal LastSeen should be stale, got %v", got)
	}
	if got := v.Put(signed(t, id, 1, 101), SourceGossip, 2); got != MergeUpdated {
		t.Fatalf("newer LastSeen should update, got %v", got)
	}
	rec, _, _ := v.Get(1)
	if rec.LastSeen != 101 {
		t.Fatalf("updated record LastSeen: %d", rec.LastSeen)
	}
}

func TestPutRejectsPublicKeyMismatch(t *testing.T) {
	v := NewMembershipView()
	a := newIdentity(t)
	b := newIdentity(t)

	v.Put(signed(t, a, 9, 100), SourceGossip, 0)
	// Different identity signing for same nodeID must be rejected.
	if got := v.Put(signed(t, b, 9, 200), SourceGossip, 0); got != MergeRejected {
		t.Fatalf("expected rejection on pubkey mismatch, got %v", got)
	}
	// Original should still be present.
	rec, _, _ := v.Get(9)
	if !bytesEqual(rec.PublicKey, a.PublicKey) {
		t.Fatalf("mismatched-key put should not clobber existing record")
	}
}

func TestReplaceFromRegistryOverwritesAnything(t *testing.T) {
	v := NewMembershipView()
	a := newIdentity(t)
	b := newIdentity(t)

	v.Put(signed(t, a, 9, 100), SourceGossip, 0)
	// Registry has authoritative new key.
	newRec := signed(t, b, 9, 99) // older even, but registry wins
	v.ReplaceFromRegistry(newRec)
	rec, src, _ := v.Get(9)
	if !bytesEqual(rec.PublicKey, b.PublicKey) {
		t.Fatalf("ReplaceFromRegistry did not overwrite pubkey")
	}
	if src != SourceRegistry {
		t.Fatalf("expected SourceRegistry, got %v", src)
	}
}

func TestDigestsSortedAscending(t *testing.T) {
	v := NewMembershipView()
	id := newIdentity(t)

	v.Put(signed(t, id, 3, 100), SourceGossip, 0)
	v.Put(signed(t, id, 1, 100), SourceGossip, 0)
	v.Put(signed(t, id, 2, 100), SourceGossip, 0)

	ds := v.Digests()
	if len(ds) != 3 {
		t.Fatalf("digest count: %d", len(ds))
	}
	for i := 1; i < len(ds); i++ {
		if ds[i-1].NodeID >= ds[i].NodeID {
			t.Fatalf("digests not ascending at %d: %+v", i, ds)
		}
	}
}

func TestPropagatableRecordsExcludesRegistrySourced(t *testing.T) {
	v := NewMembershipView()
	id := newIdentity(t)

	v.Put(signed(t, id, 1, 100), SourceGossip, 0)  // propagatable
	v.ReplaceFromRegistry(signed(t, id, 2, 100))   // not propagatable
	v.Put(signed(t, id, 3, 100), SourceLocal, 0)   // propagatable

	out := v.PropagatableRecords()
	if len(out) != 2 {
		t.Fatalf("expected 2 propagatable, got %d", len(out))
	}
	ids := map[uint32]bool{}
	for _, r := range out {
		ids[r.NodeID] = true
	}
	if ids[2] {
		t.Fatalf("registry-sourced record leaked into propagatable set")
	}
}

func TestConcurrentPutsSafe(t *testing.T) {
	v := NewMembershipView()
	id := newIdentity(t)

	var wg sync.WaitGroup
	const N = 200
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n uint32) {
			defer wg.Done()
			v.Put(signed(t, id, n, int64(1000+n)), SourceGossip, 0)
		}(uint32(i + 1))
	}
	wg.Wait()
	if v.Size() != N {
		t.Fatalf("lost entries under concurrency: size=%d, want %d", v.Size(), N)
	}
}

func TestCloneRecordIndependence(t *testing.T) {
	r := &GossipRecord{
		NodeID:    1,
		RealAddr:  "a",
		LastSeen:  1,
		PublicKey: []byte{1, 2, 3},
		Signature: []byte{4, 5, 6},
		Endpoints: []registry.NodeEndpoint{{Network: "tcp", Addr: "x"}},
	}
	c := cloneRecord(r)
	c.PublicKey[0] = 0xff
	c.Signature[0] = 0xff
	c.Endpoints[0].Addr = "y"
	if r.PublicKey[0] == 0xff || r.Signature[0] == 0xff || r.Endpoints[0].Addr == "y" {
		t.Fatalf("clone shares backing arrays with original")
	}
}
