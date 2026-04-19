package gossip

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// Transport is the narrow dependency the gossip Engine has on its
// host daemon for outbound frame delivery. Implementations wrap the
// daemon's SendGossipFrame so the gossip package stays free of a
// package cycle on daemon.
type Transport interface {
	// SendGossipFrame delivers payload as a ProtoControl packet on
	// PortGossip to dstNode over the existing encrypted tunnel. The
	// caller (Engine) has already confirmed dstNode advertises
	// CapGossip — implementations need not re-check.
	SendGossipFrame(dstNode uint32, payload []byte) error
}

// PeerSource enumerates gossip-capable peers the Engine may send
// frames to on a given tick. Implementations filter on the
// CapGossip bit as observed in the peer's most recent
// authenticated key exchange (PILA trailing varint).
type PeerSource interface {
	GossipCapablePeers() []uint32
}

// SelfFunc returns the daemon's current self-description, unsigned.
// The Engine refreshes it on every tick, stamps LastSeen = now(),
// and signs with its identity before gossiping. Callers may return
// nil while the daemon is still starting — the Engine will skip the
// tick in that case.
type SelfFunc func() *GossipRecord

// KeyLookup resolves a node_id to its pinned Ed25519 public key so
// the Engine can verify inbound gossip record signatures against a
// known identity. Returns (nil, false) when the key is not yet
// known — in that case the Engine accepts the record via TOFU and
// will cross-check the pinned key on the next registry resolve.
// Implementations typically read TunnelManager.peerPubKeys.
type KeyLookup func(nodeID uint32) (ed25519.PublicKey, bool)

// Frame is the JSON envelope that rides inside a PortGossip control
// payload. A single frame is either a sync (digests only — "what
// do you know") or a delta (records — "here's what you're missing").
// A two-frame tick (sync → delta) propagates one-way; full
// convergence between two peers takes two ticks in the general case.
type Frame struct {
	Type    string         `json:"t"`
	Digests []GossipDigest `json:"d,omitempty"`
	Records []GossipRecord `json:"r,omitempty"`
}

const (
	frameTypeSync  = "sync"
	frameTypeDelta = "delta"

	// DefaultInterval is the periodic tick cadence. Matches the
	// beaconKeepaliveLoop cadence so both timers share a 25-second
	// NAT-mapping refresh budget.
	DefaultInterval = 25 * time.Second
)

// Engine drives the gossip protocol: periodic sync with a random
// gossip-capable peer, plus reactive responses to inbound sync
// frames. One engine per daemon.
type Engine struct {
	id       *crypto.Identity
	view     *MembershipView
	tr       Transport
	peers    PeerSource
	selfFn   SelfFunc
	keyLook  KeyLookup
	interval time.Duration

	// Source of randomness for peer selection. Instantiated per
	// Engine so tests can seed deterministically; defaults to
	// crypto-grade randomness via time.Now nanoseconds.
	rng *rand.Rand

	startOnce sync.Once
	stopOnce  sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewEngine builds an Engine ready for Start. All arguments are
// required; nil pointers panic early on first use.
//
// If interval is zero, DefaultInterval is used.
func NewEngine(id *crypto.Identity, view *MembershipView, tr Transport, peers PeerSource, selfFn SelfFunc, keyLook KeyLookup, interval time.Duration) *Engine {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Engine{
		id:       id,
		view:     view,
		tr:       tr,
		peers:    peers,
		selfFn:   selfFn,
		keyLook:  keyLook,
		interval: interval,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		done:     make(chan struct{}),
	}
}

// Start begins the background ticker. Idempotent; subsequent calls
// are no-ops so a supervisor can blindly re-enter. Caller retains
// responsibility for Stop.
func (e *Engine) Start() {
	e.startOnce.Do(func() {
		e.wg.Add(1)
		go e.tickLoop()
	})
}

// Stop signals the background ticker to exit and waits up to a
// generous 2-second drain for it to return. Idempotent.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.done)
	})
	// Wait is safe to call even if Start was never called (wg counter
	// is zero and Wait returns immediately).
	e.wg.Wait()
}

// Tick runs a single gossip round synchronously. Exported for tests
// and for integration hooks that want to trigger a round outside the
// normal cadence (e.g. after a batch of registrations).
func (e *Engine) Tick() {
	e.refreshSelf()
	target := e.pickTarget()
	if target == 0 {
		return
	}
	if err := e.sendSync(target); err != nil {
		slog.Debug("gossip: tick send failed", "peer", target, "error", err)
	}
}

// PushTo sends the sender's full propagatable view to dstNode as an
// unsolicited delta. Used on fresh-handshake completion to let new
// peers catch up in one round-trip instead of waiting for a tick.
func (e *Engine) PushTo(dstNode uint32) {
	e.refreshSelf()
	recs := e.view.PropagatableRecords()
	if len(recs) == 0 {
		return
	}
	payload, err := json.Marshal(Frame{Type: frameTypeDelta, Records: recs})
	if err != nil {
		slog.Debug("gossip: marshal delta for push", "peer", dstNode, "error", err)
		return
	}
	if err := e.tr.SendGossipFrame(dstNode, payload); err != nil {
		slog.Debug("gossip: opportunistic push failed", "peer", dstNode, "error", err)
	}
}

// OnInbound is the entry point for gossip frames arriving via the
// daemon's handleControlPacket → gossip handler chain. Payload is
// the JSON body of the ProtoControl packet.
func (e *Engine) OnInbound(srcNode uint32, payload []byte) {
	var f Frame
	if err := json.Unmarshal(payload, &f); err != nil {
		slog.Debug("gossip: malformed frame", "src", srcNode, "error", err)
		return
	}
	switch f.Type {
	case frameTypeSync:
		e.handleSync(srcNode, f.Digests)
	case frameTypeDelta:
		e.handleDelta(srcNode, f.Records)
	default:
		slog.Debug("gossip: unknown frame type", "src", srcNode, "type", f.Type)
	}
}

// refreshSelf re-signs and stores the daemon's own advertisement
// with the current wall-clock as LastSeen. Called at the top of
// every tick so other peers observe a monotonically increasing
// timestamp from us, and skipped when selfFn returns nil (daemon
// still starting up).
func (e *Engine) refreshSelf() {
	if e.selfFn == nil {
		return
	}
	r := e.selfFn()
	if r == nil || r.NodeID == 0 {
		return
	}
	r.LastSeen = time.Now().Unix()
	if len(r.PublicKey) == 0 && e.id != nil {
		r.PublicKey = e.id.PublicKey
	}
	if err := Sign(r, e.id); err != nil {
		slog.Debug("gossip: sign self record", "error", err)
		return
	}
	e.view.Put(r, SourceLocal, 0)
}

// pickTarget returns a random gossip-capable peer, or 0 if there
// are none. The engine is expected to tolerate the 0 case (no-op
// tick) rather than block.
func (e *Engine) pickTarget() uint32 {
	peers := e.peers.GossipCapablePeers()
	if len(peers) == 0 {
		return 0
	}
	return peers[e.rng.Intn(len(peers))]
}

// sendSync pushes our current digests to target. The responder will
// reply with a delta covering whichever of our digests are stale
// from their perspective.
func (e *Engine) sendSync(target uint32) error {
	f := Frame{Type: frameTypeSync, Digests: e.view.Digests()}
	payload, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal sync: %w", err)
	}
	return e.tr.SendGossipFrame(target, payload)
}

// handleSync is invoked on inbound sync frames. We compute the set
// of propagatable records whose LastSeen exceeds the sender's
// corresponding digest (or that the sender lacks entirely) and
// reply with a delta.
//
// The responder refreshes its own self-record before computing the
// delta so that in the common two-peer case (initiator sends sync,
// responder replies with delta) full mutual convergence happens in
// a single round: the initiator learns about the responder from
// the delta, without having to wait for the responder's own tick.
// The cost is one ed25519 sign per inbound sync — negligible.
func (e *Engine) handleSync(srcNode uint32, theirDigests []GossipDigest) {
	e.refreshSelf()
	theirKnown := make(map[uint32]int64, len(theirDigests))
	for _, d := range theirDigests {
		theirKnown[d.NodeID] = d.LastSeen
	}
	ours := e.view.PropagatableRecords()
	toSend := ours[:0]
	for _, r := range ours {
		if theirLast, known := theirKnown[r.NodeID]; !known || r.LastSeen > theirLast {
			toSend = append(toSend, r)
		}
	}
	if len(toSend) == 0 {
		return
	}
	payload, err := json.Marshal(Frame{Type: frameTypeDelta, Records: toSend})
	if err != nil {
		slog.Debug("gossip: marshal delta reply", "peer", srcNode, "error", err)
		return
	}
	if err := e.tr.SendGossipFrame(srcNode, payload); err != nil {
		slog.Debug("gossip: delta reply send", "peer", srcNode, "error", err)
	}
}

// handleDelta is invoked on inbound delta frames. Each record is
// verified (against the pinned key if we have one, TOFU otherwise)
// and, if valid, merged into our view.
func (e *Engine) handleDelta(srcNode uint32, records []GossipRecord) {
	for i := range records {
		r := &records[i]
		// Shallow clone — Put stores its own deep copy, but verify
		// works on whatever fields we pass.
		if err := e.acceptRecord(r, srcNode); err != nil {
			slog.Debug("gossip: reject record", "from", srcNode, "subject", r.NodeID, "error", err)
		}
	}
}

// acceptRecord verifies r and, on success, merges into the view.
// Separate from handleDelta for testability.
func (e *Engine) acceptRecord(r *GossipRecord, fromPeer uint32) error {
	if r == nil {
		return errors.New("nil record")
	}
	var expected ed25519.PublicKey
	if e.keyLook != nil {
		if pk, ok := e.keyLook(r.NodeID); ok {
			expected = pk
		}
	}
	if err := Verify(r, expected); err != nil {
		return err
	}
	res := e.view.Put(r, SourceGossip, fromPeer)
	if res == MergeRejected {
		return errors.New("rejected by view policy (pubkey mismatch)")
	}
	return nil
}
