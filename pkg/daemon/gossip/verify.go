package gossip

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// ErrSignatureInvalid is returned when a record's Signature does not
// verify under its advertised PublicKey.
var ErrSignatureInvalid = errors.New("gossip: signature invalid")

// ErrPublicKeyMismatch is returned when a record's PublicKey does
// not match the key the caller expected (e.g., what the registry
// previously bound to this NodeID, or the TOFU-pinned value).
var ErrPublicKeyMismatch = errors.New("gossip: public key mismatch")

// Sign fills in r.Signature by signing canonicalBytes(r) with the
// given identity's private key. Also ensures r.PublicKey is
// populated from the identity (required for downstream Verify).
// Mutates r in place.
func Sign(r *GossipRecord, id *crypto.Identity) error {
	if id == nil || len(id.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("gossip: sign: identity missing or malformed")
	}
	if len(r.PublicKey) == 0 {
		r.PublicKey = id.PublicKey
	}
	if err := validateShape(r); err != nil {
		return err
	}
	r.Signature = id.Sign(canonicalBytes(r))
	return nil
}

// Verify checks the record's signature against its own PublicKey.
// Callers that have an out-of-band expectation for what the
// PublicKey should be (e.g. a value pinned from the registry) pass
// it in expectedPubKey; if non-nil, the record's PublicKey must
// match bit-for-bit. Pass nil for TOFU acceptance.
//
// Returns nil on success; ErrSignatureInvalid or
// ErrPublicKeyMismatch on the respective failure.
func Verify(r *GossipRecord, expectedPubKey ed25519.PublicKey) error {
	if err := validateShape(r); err != nil {
		return err
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	if expectedPubKey != nil && !bytes.Equal(expectedPubKey, r.PublicKey) {
		return ErrPublicKeyMismatch
	}
	if !crypto.Verify(r.PublicKey, canonicalBytes(r), r.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}
