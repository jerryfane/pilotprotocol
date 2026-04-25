// Package rendezvous implements the Pkarr-style endpoint rendezvous
// client and shared blob format used by Pilot v1.9.0-jf.14 to fix the
// cold-start bootstrap deadlock that survives jf.13's keepalive.
//
// Why this exists. jf.13's per-peer keepalive (WireGuard
// PersistentKeepalive) keeps the TURN-permission window warm for
// already-authenticated peers, which solves steady-state. It does NOT
// solve cold start: a freshly-restarted peer holds a new TURN
// allocation address, and its peers can only learn that address via a
// channel that itself rides on tunnels which don't exist yet (gossip)
// or via the centralized registry, which the privacy-maximalist
// preset (-hide-ip + -outbound-turn-only + -no-registry-endpoint)
// explicitly opts out of. With both channels unavailable, no
// authenticated tunnel can ever form. The rendezvous is the third
// independent endpoint-distribution channel — a tiny ed25519-signed
// (NodeID -> TURN_endpoint) record served by an HTTP service the
// operator controls. Same architectural shape iroh ships in
// production via iroh-dns-server.
//
// Trust model. The service is trusted for AVAILABILITY but not for
// integrity. Records are signed by each peer's ed25519 identity (the
// same key Pilot already loads from identity.json). A compromised
// service cannot forge endpoints (signatures fail) and cannot learn
// real IPs (records hold only Cloudflare-anycast TURN allocation
// addresses). It can enumerate NodeIDs that have published and
// selectively withhold blobs. Both are strict subsets of the
// existing gossip-layer leakage surface.
package rendezvous

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// SignatureDomain is the domain-separation prefix for every
// rendezvous signature. Including it in the canonical payload
// prevents a signature minted here from being replayed in any
// other Pilot/Entmoot signature surface (gossip, handshake,
// invites). The trailing NUL is part of the prefix.
const SignatureDomain = "pilot-rendezvous/v1\x00"

// MaxTURNEndpointLen caps the TURN endpoint string at a length
// large enough for any "host:port" form (incl. IPv6 + 5-digit
// port) but small enough to bound parser work. Server and client
// both enforce.
const MaxTURNEndpointLen = 64

// MaxValidityWindow is the longest IssuedAt..ValidUntil span the
// server accepts on PUT. Defends against a peer publishing a
// near-immortal blob that survives long after the keys leak.
const MaxValidityWindow = 1 * time.Hour

// ClockSkewTolerance is the maximum |IssuedAt - server clock|
// difference accepted on PUT. Loose enough to absorb realistic
// NTP drift across continents; tight enough that an attacker
// can't backfill the bbolt store with year-old blobs.
const ClockSkewTolerance = 5 * time.Minute

// AnnounceBlob is the wire-format record stored at the rendezvous,
// keyed by NodeID. Field tags are JSON because the rendezvous
// endpoint is HTTP+JSON; the canonical signing payload below is a
// fixed binary encoding so signatures verify byte-identically
// regardless of JSON whitespace.
type AnnounceBlob struct {
	NodeID       uint32 `json:"node_id"`
	PublicKey    []byte `json:"public_key"`    // ed25519, 32 bytes
	TURNEndpoint string `json:"turn_endpoint"` // "host:port"
	IssuedAt     int64  `json:"issued_at"`     // unix ms
	ValidUntil   int64  `json:"valid_until"`   // unix ms
	Signature    []byte `json:"signature"`     // ed25519 over canonicalPayload, 64 bytes
}

// canonicalPayload returns the byte string both Sign and Verify run
// ed25519 against. Format:
//
//	SignatureDomain
//	|| u32be(NodeID)
//	|| u8(len(PublicKey)) || PublicKey
//	|| u8(len(TURNEndpoint)) || TURNEndpoint
//	|| u64be(IssuedAt)
//	|| u64be(ValidUntil)
//
// Length-prefixing every variable field eliminates any ambiguity
// across encoders/decoders.
func canonicalPayload(nodeID uint32, publicKey ed25519.PublicKey, turnEndpoint string, issuedAt, validUntil int64) []byte {
	out := make([]byte, 0,
		len(SignatureDomain)+4+1+len(publicKey)+1+len(turnEndpoint)+8+8)
	out = append(out, SignatureDomain...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], nodeID)
	out = append(out, u32[:]...)
	out = append(out, byte(len(publicKey)))
	out = append(out, publicKey...)
	out = append(out, byte(len(turnEndpoint)))
	out = append(out, turnEndpoint...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(issuedAt))
	out = append(out, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], uint64(validUntil))
	out = append(out, u64[:]...)
	return out
}

// Sign builds a fully-populated AnnounceBlob signed by id.
//
//	now    : current wall time. The caller passes it explicitly so
//	         tests can inject a fixed clock.
//	ttl    : desired ValidUntil - IssuedAt window. Capped to
//	         MaxValidityWindow.
//	nodeID : the peer's Pilot node_id (stable across restarts when
//	         identity persists).
//	turnEp : "host:port" of the local TURN allocation we want
//	         peers to dial when they need to reach us.
func Sign(id *crypto.Identity, nodeID uint32, turnEp string, now time.Time, ttl time.Duration) (*AnnounceBlob, error) {
	if id == nil || len(id.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("sign: identity missing or invalid")
	}
	if turnEp == "" {
		return nil, errors.New("sign: turn endpoint empty")
	}
	if len(turnEp) > MaxTURNEndpointLen {
		return nil, fmt.Errorf("sign: turn endpoint too long (%d > %d)", len(turnEp), MaxTURNEndpointLen)
	}
	if ttl <= 0 {
		return nil, errors.New("sign: ttl must be > 0")
	}
	if ttl > MaxValidityWindow {
		ttl = MaxValidityWindow
	}
	issuedAt := now.UnixMilli()
	validUntil := issuedAt + ttl.Milliseconds()
	payload := canonicalPayload(nodeID, id.PublicKey, turnEp, issuedAt, validUntil)
	sig := ed25519.Sign(id.PrivateKey, payload)
	pkCopy := make([]byte, len(id.PublicKey))
	copy(pkCopy, id.PublicKey)
	return &AnnounceBlob{
		NodeID:       nodeID,
		PublicKey:    pkCopy,
		TURNEndpoint: turnEp,
		IssuedAt:     issuedAt,
		ValidUntil:   validUntil,
		Signature:    sig,
	}, nil
}

// Verify checks the signature, the field bounds, and the validity
// window against `now`. Optional `expectedNodeID` and
// `expectedPubkey` are out-of-band bindings the caller already
// trusts — when supplied, the blob's NodeID/PublicKey MUST equal
// them. Pass zero / nil to skip those checks (server uses them on
// initial PUT for TOFU; client uses them on Lookup if it has
// roster bindings — jf.14 client passes nil, jf.15 will pass the
// roster value).
//
// `now` is taken explicitly for the same reason as Sign.
func (b *AnnounceBlob) Verify(now time.Time, expectedNodeID uint32, expectedPubkey ed25519.PublicKey) error {
	if b == nil {
		return errors.New("blob: nil")
	}
	if len(b.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("blob: public key size %d != %d", len(b.PublicKey), ed25519.PublicKeySize)
	}
	if len(b.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("blob: signature size %d != %d", len(b.Signature), ed25519.SignatureSize)
	}
	if b.TURNEndpoint == "" {
		return errors.New("blob: turn endpoint empty")
	}
	if len(b.TURNEndpoint) > MaxTURNEndpointLen {
		return fmt.Errorf("blob: turn endpoint too long (%d > %d)", len(b.TURNEndpoint), MaxTURNEndpointLen)
	}
	if b.ValidUntil <= b.IssuedAt {
		return errors.New("blob: validity window non-positive")
	}
	if (b.ValidUntil - b.IssuedAt) > MaxValidityWindow.Milliseconds() {
		return fmt.Errorf("blob: validity window too long (%d > %d ms)",
			b.ValidUntil-b.IssuedAt, MaxValidityWindow.Milliseconds())
	}
	nowMs := now.UnixMilli()
	if nowMs > b.ValidUntil {
		return fmt.Errorf("blob: expired (now=%d > valid_until=%d)", nowMs, b.ValidUntil)
	}
	if expectedNodeID != 0 && b.NodeID != expectedNodeID {
		return fmt.Errorf("blob: node_id mismatch (got %d, want %d)", b.NodeID, expectedNodeID)
	}
	if expectedPubkey != nil && !ed25519.PublicKey(b.PublicKey).Equal(expectedPubkey) {
		return errors.New("blob: public key does not match expected binding")
	}
	payload := canonicalPayload(b.NodeID, b.PublicKey, b.TURNEndpoint, b.IssuedAt, b.ValidUntil)
	if !ed25519.Verify(b.PublicKey, payload, b.Signature) {
		return errors.New("blob: invalid signature")
	}
	return nil
}

// VerifyPUT is Verify plus the additional clock-skew check the
// server applies on PUT (rejects blobs from peers with badly
// drifted clocks before they pollute the store). Clients on
// Lookup do not run this — they care only about the signature
// and ValidUntil — but the server treats IssuedAt skew as
// adversarial.
func (b *AnnounceBlob) VerifyPUT(now time.Time) error {
	if err := b.Verify(now, 0, nil); err != nil {
		return err
	}
	skew := time.Duration(now.UnixMilli()-b.IssuedAt) * time.Millisecond
	if skew < 0 {
		skew = -skew
	}
	if skew > ClockSkewTolerance {
		return fmt.Errorf("blob: issued_at clock skew %s > %s", skew, ClockSkewTolerance)
	}
	return nil
}
