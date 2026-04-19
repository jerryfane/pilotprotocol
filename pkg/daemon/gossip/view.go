package gossip

import (
	"sync"
	"time"
)

// Source tags how a MembershipView entry came to exist. It matters
// because only self-signed records (source = SourceGossip) are
// propagatable — the registry-sourced entries serve local lookup
// only, since we don't have a signature to forward.
type Source uint8

const (
	// SourceUnknown is the zero value; should not appear in a stored
	// entry. Guarded by Put helpers.
	SourceUnknown Source = 0
	// SourceRegistry marks an entry populated from the registry's
	// lookup/resolve response. No signature; Verify is skipped on
	// insertion and the entry is NOT forwarded via gossip.
	SourceRegistry Source = 1
	// SourceGossip marks an entry that arrived via gossip and passed
	// signature verification. Eligible for forwarding.
	SourceGossip Source = 2
	// SourceLocal marks the daemon's own self-signed record, which it
	// publishes to peers. Same propagation rules as SourceGossip.
	SourceLocal Source = 3
)

// viewEntry stores a record plus local bookkeeping. The bookkeeping
// is not part of the wire format.
type viewEntry struct {
	record     GossipRecord
	source     Source
	receivedAt time.Time // local wall-clock at insertion
	fromPeer   uint32    // 0 if local / registry / unknown
}

// MembershipView is the in-memory directory each daemon maintains.
// Thread-safe; the Engine goroutine reads/writes it alongside
// on-demand lookups from dialer goroutines.
type MembershipView struct {
	mu      sync.RWMutex
	entries map[uint32]*viewEntry
}

// NewMembershipView returns an empty view.
func NewMembershipView() *MembershipView {
	return &MembershipView{entries: make(map[uint32]*viewEntry)}
}

// MergeResult describes how a Put affected the view. Useful for
// engine-side logging and metrics.
type MergeResult uint8

const (
	// MergeInserted: no prior entry for this NodeID, the record was
	// accepted.
	MergeInserted MergeResult = iota
	// MergeUpdated: prior entry existed, the new record was strictly
	// newer by LastSeen and replaced it.
	MergeUpdated
	// MergeStale: new record rejected because LastSeen <= existing
	// entry's LastSeen. Common and expected — not a problem.
	MergeStale
	// MergeRejected: record rejected for a structural / policy
	// reason (e.g. pubkey mismatch on a prior entry).
	MergeRejected
)

// Put tries to insert or merge a record into the view. The caller
// is responsible for having verified the signature (for gossip
// source) before calling.
//
// The merge rule is LastSeen-strict: a new record replaces an old
// one only if its LastSeen is strictly greater. Equal LastSeen on
// different content is a signing anomaly — a correctly-behaved node
// should bump LastSeen every time it resigns. We treat equal as
// stale to be conservative.
//
// If an existing entry has a different PublicKey for the same
// NodeID, the new record is rejected (MergeRejected). The registry
// is the tie-breaker: a caller who suspects a legitimate key
// rotation should overwrite via ReplaceFromRegistry.
func (v *MembershipView) Put(r *GossipRecord, source Source, fromPeer uint32) MergeResult {
	if r == nil || source == SourceUnknown {
		return MergeRejected
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	existing, ok := v.entries[r.NodeID]
	if !ok {
		v.entries[r.NodeID] = &viewEntry{
			record:     cloneRecord(r),
			source:     source,
			receivedAt: time.Now(),
			fromPeer:   fromPeer,
		}
		return MergeInserted
	}
	if !pubKeyEqual(existing.record.PublicKey, r.PublicKey) {
		// Key mismatch under the same NodeID — registry has to
		// arbitrate. Refuse to overwrite silently.
		return MergeRejected
	}
	if r.LastSeen <= existing.record.LastSeen {
		return MergeStale
	}
	existing.record = cloneRecord(r)
	existing.source = source
	existing.receivedAt = time.Now()
	existing.fromPeer = fromPeer
	return MergeUpdated
}

// ReplaceFromRegistry is the escape hatch used when the registry
// authoritatively contradicts a gossip-learned record (e.g. legit
// key rotation). Unconditionally replaces whatever was there.
func (v *MembershipView) ReplaceFromRegistry(r *GossipRecord) {
	if r == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries[r.NodeID] = &viewEntry{
		record:     cloneRecord(r),
		source:     SourceRegistry,
		receivedAt: time.Now(),
	}
}

// Get returns a copy of the stored record for nodeID, plus its
// source. Returns (zero, SourceUnknown, false) when absent.
func (v *MembershipView) Get(nodeID uint32) (GossipRecord, Source, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.entries[nodeID]
	if !ok {
		return GossipRecord{}, SourceUnknown, false
	}
	return cloneRecord(&e.record), e.source, true
}

// Digests returns one GossipDigest per known entry — the payload of
// a GossipSync frame. Stable ordering: ascending NodeID.
func (v *MembershipView) Digests() []GossipDigest {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]GossipDigest, 0, len(v.entries))
	for id, e := range v.entries {
		out = append(out, GossipDigest{NodeID: id, LastSeen: e.record.LastSeen})
	}
	sortDigestsByNodeID(out)
	return out
}

// PropagatableRecords returns a snapshot of records whose Source
// allows forwarding (SourceGossip or SourceLocal). Used to compute
// the response to a GossipSync.
func (v *MembershipView) PropagatableRecords() []GossipRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]GossipRecord, 0, len(v.entries))
	for _, e := range v.entries {
		if e.source == SourceGossip || e.source == SourceLocal {
			out = append(out, cloneRecord(&e.record))
		}
	}
	return out
}

// Size returns the number of entries currently stored. Intended for
// metrics / tests.
func (v *MembershipView) Size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

func cloneRecord(r *GossipRecord) GossipRecord {
	c := *r
	if len(r.PublicKey) > 0 {
		c.PublicKey = append([]byte(nil), r.PublicKey...)
	}
	if len(r.Signature) > 0 {
		c.Signature = append([]byte(nil), r.Signature...)
	}
	if len(r.Endpoints) > 0 {
		c.Endpoints = append(c.Endpoints[:0:0], r.Endpoints...)
	}
	return c
}

func pubKeyEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortDigestsByNodeID sorts in place. Avoids sort.Slice allocation
// for the small slices we pass here.
func sortDigestsByNodeID(ds []GossipDigest) {
	// Simple insertion sort — Digests slices are small (O(N peers),
	// realistically < a few hundred). Insertion sort avoids pulling in
	// sort.Slice's closure allocation on hot paths.
	for i := 1; i < len(ds); i++ {
		j := i
		for j > 0 && ds[j-1].NodeID > ds[j].NodeID {
			ds[j-1], ds[j] = ds[j], ds[j-1]
			j--
		}
	}
}
