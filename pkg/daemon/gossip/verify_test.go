package gossip

import (
	"errors"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

func newIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func TestSignThenVerifyRoundTrip(t *testing.T) {
	id := newIdentity(t)
	r := sampleRecord()
	r.PublicKey = id.PublicKey

	if err := Sign(r, id); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(r, nil); err != nil {
		t.Fatalf("verify (TOFU): %v", err)
	}
	if err := Verify(r, id.PublicKey); err != nil {
		t.Fatalf("verify with expected key: %v", err)
	}
}

func TestSignPopulatesPublicKeyWhenUnset(t *testing.T) {
	id := newIdentity(t)
	r := sampleRecord()
	r.PublicKey = nil

	if err := Sign(r, id); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytesEqual(r.PublicKey, id.PublicKey) {
		t.Fatalf("Sign should populate PublicKey from identity")
	}
}

func TestVerifyRejectsTamperedRecord(t *testing.T) {
	id := newIdentity(t)
	r := sampleRecord()
	if err := Sign(r, id); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Flip a single byte in a signed field; signature must not verify.
	r.RealAddr = "203.0.113.7:99999"
	if err := Verify(r, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered record verified: err=%v", err)
	}
}

func TestVerifyRejectsMismatchedExpectedKey(t *testing.T) {
	authorID := newIdentity(t)
	otherID := newIdentity(t)
	r := sampleRecord()
	if err := Sign(r, authorID); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(r, otherID.PublicKey); !errors.Is(err, ErrPublicKeyMismatch) {
		t.Fatalf("expected ErrPublicKeyMismatch, got %v", err)
	}
}

func TestVerifyRejectsMissingSignature(t *testing.T) {
	id := newIdentity(t)
	r := sampleRecord()
	r.PublicKey = id.PublicKey
	// No Sign call — signature stays empty.
	if err := Verify(r, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid on unsigned record, got %v", err)
	}
}

func TestVerifyRejectsShapeViolations(t *testing.T) {
	id := newIdentity(t)
	cases := []func(*GossipRecord){
		func(r *GossipRecord) { r.NodeID = 0 },
		func(r *GossipRecord) { r.RealAddr = "" },
		func(r *GossipRecord) { r.LastSeen = 0 },
		func(r *GossipRecord) { r.PublicKey = []byte{0x01, 0x02} }, // wrong length
	}
	for i, mut := range cases {
		r := sampleRecord()
		r.PublicKey = id.PublicKey
		if err := Sign(r, id); err != nil {
			t.Fatalf("case %d sign: %v", i, err)
		}
		mut(r)
		if err := Verify(r, nil); err == nil {
			t.Errorf("case %d: expected shape-violation error, got nil", i)
		}
	}
}

func TestSignRefusesMalformedIdentity(t *testing.T) {
	r := sampleRecord()
	if err := Sign(r, nil); err == nil {
		t.Errorf("expected error on nil identity")
	}
	bad := &crypto.Identity{PrivateKey: []byte{0x01}}
	if err := Sign(r, bad); err == nil {
		t.Errorf("expected error on malformed private key")
	}
}

func bytesEqual(a, b []byte) bool {
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
