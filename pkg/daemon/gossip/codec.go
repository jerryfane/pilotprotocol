// Package gossip implements Pilot's peer-discovery overlay: an
// additive, registry-complementing layer in which each daemon
// maintains a signed membership view and exchanges deltas with
// random peers on a short periodic tick. The goal is to decouple
// Pilot's multi-transport (UDP/TCP/…) endpoint propagation from
// registry cooperation. Upgraded daemons learn new capability fields
// from each other over the encrypted tunnel; stock daemons keep
// working via the registry as today.
//
// Wire form: gossip frames ride as ProtoControl payloads on the
// peer's ProtoControl port reserved for gossip (see
// pkg/protocol/ports.go PortGossip constant once Phase C lands).
// This makes the frames invisible to network observers (tunnel
// encryption) and transparent to older daemons (unknown control
// ports are silently dropped by the default branch of
// handleControlPacket in daemon.go).
//
// Identity model: each record is self-signed by the owning node's
// Ed25519 private key. The registry remains the authoritative
// (node_id ↔ public_key) binding; the gossip layer uses
// pin-on-first-use and cross-checks against the registry on a slow
// interval.
package gossip

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
)

// GossipRecord is one node's self-signed advertisement. Peers
// exchange these to propagate membership and multi-transport
// endpoint information without going through the registry.
//
// A record is authoritative only when the Signature verifies under
// the record's own PublicKey and when that PublicKey matches what
// the registry (or a prior accepted gossip record) has bound to
// NodeID. The verify.go file encodes those rules.
//
// LastSeen is the author's own wall-clock at signing time (Unix
// seconds). It drives the merge rule — a newer LastSeen replaces an
// older one — and defeats stale-record replay.
type GossipRecord struct {
	NodeID    uint32                  `json:"node_id"`
	PublicKey ed25519.PublicKey       `json:"public_key"`
	RealAddr  string                  `json:"real_addr"`
	Endpoints []registry.NodeEndpoint `json:"endpoints,omitempty"`
	Hostname  string                  `json:"hostname,omitempty"`
	LastSeen  int64                   `json:"last_seen"`
	Signature []byte                  `json:"signature,omitempty"`
}

// GossipDigest summarizes what a peer knows about a single node.
// Used inside GossipSync so the responder can compute the delta
// without sending the full view.
type GossipDigest struct {
	NodeID   uint32 `json:"node_id"`
	LastSeen int64  `json:"last_seen"`
}

// GossipSync is the "what do you know" frame. The initiator lists
// one digest per node it currently knows about; the responder
// compares each against its own view and constructs a GossipDelta.
type GossipSync struct {
	Digests []GossipDigest `json:"digests"`
}

// GossipDelta is the response frame (or an unsolicited push, e.g.
// right after a new peer handshake). Records carries any records the
// sender believes the recipient is missing or has stale. Missing
// lists node_ids the sender lacks and would like bodies for; a
// follow-up GossipDelta carrying those records is expected.
type GossipDelta struct {
	Records []GossipRecord `json:"records"`
	Missing []uint32       `json:"missing,omitempty"`
}

// canonicalBytes serializes a record's signed fields into a
// deterministic byte string. The encoding is intentionally codec-
// independent (does not rely on JSON map ordering) so that any
// implementation can reproduce the exact bytes for verification.
//
// Layout (big-endian where relevant):
//
//	"pilot-gossip-v1\x00"                          (16-byte tag)
//	uint32   NodeID
//	uint16   len(PublicKey) || PublicKey bytes
//	uint16   len(RealAddr)  || RealAddr bytes
//	uint16   len(Hostname)  || Hostname bytes
//	int64    LastSeen
//	uint16   N endpoints (sorted)
//	  for each: uint16 len(Network) || Network  ||
//	            uint16 len(Addr)    || Addr
//
// Endpoints are sorted by (Network, Addr) ASCII before encoding so
// two peers with the same semantic record always produce the same
// canonical bytes regardless of input order.
func canonicalBytes(r *GossipRecord) []byte {
	var buf bytes.Buffer
	buf.WriteString("pilot-gossip-v1\x00")

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], r.NodeID)
	buf.Write(u32[:])

	writeBlob := func(b []byte) {
		var u16 [2]byte
		binary.BigEndian.PutUint16(u16[:], uint16(len(b)))
		buf.Write(u16[:])
		buf.Write(b)
	}
	writeStr := func(s string) { writeBlob([]byte(s)) }

	writeBlob(r.PublicKey)
	writeStr(r.RealAddr)
	writeStr(r.Hostname)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(r.LastSeen))
	buf.Write(ts[:])

	eps := append([]registry.NodeEndpoint(nil), r.Endpoints...)
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Network != eps[j].Network {
			return eps[i].Network < eps[j].Network
		}
		return eps[i].Addr < eps[j].Addr
	})
	var epCount [2]byte
	binary.BigEndian.PutUint16(epCount[:], uint16(len(eps)))
	buf.Write(epCount[:])
	for _, e := range eps {
		writeStr(e.Network)
		writeStr(e.Addr)
	}

	return buf.Bytes()
}

// MarshalRecord JSON-encodes a record for on-wire transport.
// Separate from canonicalBytes because wire form carries the
// signature and can vary by codec; canonical bytes are fixed.
func MarshalRecord(r *GossipRecord) ([]byte, error) { return json.Marshal(r) }

// UnmarshalRecord reverses MarshalRecord. Does NOT verify the
// signature — verify.go handles that.
func UnmarshalRecord(data []byte) (*GossipRecord, error) {
	var r GossipRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("gossip: unmarshal record: %w", err)
	}
	return &r, nil
}

// MarshalSync/UnmarshalSync and MarshalDelta/UnmarshalDelta are the
// corresponding helpers for the envelope message types.
func MarshalSync(s *GossipSync) ([]byte, error)     { return json.Marshal(s) }
func MarshalDelta(d *GossipDelta) ([]byte, error)   { return json.Marshal(d) }
func UnmarshalSync(data []byte) (*GossipSync, error) {
	var s GossipSync
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("gossip: unmarshal sync: %w", err)
	}
	return &s, nil
}
func UnmarshalDelta(data []byte) (*GossipDelta, error) {
	var d GossipDelta
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("gossip: unmarshal delta: %w", err)
	}
	return &d, nil
}

// ErrRecordIncomplete is returned when a record is missing required
// fields (NodeID, PublicKey of correct size, RealAddr, LastSeen).
// Signature absence is NOT covered here — verify.go catches that.
var ErrRecordIncomplete = errors.New("gossip: record missing required fields")

// validateShape enforces the structural invariants every record
// must satisfy before it's worth hashing or verifying. Run before
// Sign and before Verify.
func validateShape(r *GossipRecord) error {
	if r == nil || r.NodeID == 0 || len(r.PublicKey) != ed25519.PublicKeySize || r.RealAddr == "" || r.LastSeen == 0 {
		return ErrRecordIncomplete
	}
	return nil
}
