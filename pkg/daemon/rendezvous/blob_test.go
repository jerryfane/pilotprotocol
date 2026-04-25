package rendezvous

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

// freshIdentity returns a brand-new ed25519 identity for use in
// tests. Equivalent to crypto.GenerateIdentity but local so tests
// don't depend on its implementation choice.
func freshIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return &crypto.Identity{PublicKey: pub, PrivateKey: priv}
}

// TestSign_RoundTrip verifies the canonical-payload contract: a
// blob produced by Sign verifies cleanly under Verify with the
// same time and same identity. This is the happy path; everything
// downstream (server PUT, client Lookup) depends on it being
// byte-for-byte deterministic.
func TestSign_RoundTrip(t *testing.T) {
	id := freshIdentity(t)
	now := time.Date(2026, 4, 25, 19, 30, 0, 0, time.UTC)
	blob, err := Sign(id, 45491, "104.30.150.206:49529", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if blob.NodeID != 45491 {
		t.Fatalf("NodeID: got %d, want 45491", blob.NodeID)
	}
	if blob.TURNEndpoint != "104.30.150.206:49529" {
		t.Fatalf("TURNEndpoint: got %q", blob.TURNEndpoint)
	}
	if len(blob.Signature) != ed25519.SignatureSize {
		t.Fatalf("Signature size: %d", len(blob.Signature))
	}
	if !ed25519.PublicKey(blob.PublicKey).Equal(id.PublicKey) {
		t.Fatalf("blob PublicKey != identity PublicKey")
	}
	if err := blob.Verify(now, 0, nil); err != nil {
		t.Fatalf("Verify of freshly-signed blob: %v", err)
	}
	// And with explicit expected bindings:
	if err := blob.Verify(now, 45491, id.PublicKey); err != nil {
		t.Fatalf("Verify with expected bindings: %v", err)
	}
}

// TestVerify_TamperedSignature: any single-bit flip in the
// signature must fail verification. This is the load-bearing
// guarantee that justifies trusting an opaque-storage rendezvous.
func TestVerify_TamperedSignature(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 1, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	blob.Signature[0] ^= 0x01
	if err := blob.Verify(now, 0, nil); err == nil {
		t.Fatalf("Verify accepted tampered signature")
	}
}

// TestVerify_TamperedTURNEndpoint: changing the endpoint after
// signing breaks verification — exactly what we need to prevent
// a rendezvous server from substituting an attacker-controlled
// endpoint.
func TestVerify_TamperedTURNEndpoint(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 1, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	blob.TURNEndpoint = "evil.example.com:9999"
	if err := blob.Verify(now, 0, nil); err == nil {
		t.Fatalf("Verify accepted tampered endpoint")
	}
}

// TestVerify_TamperedNodeID: similarly, swapping NodeID to a
// different peer's ID must be detected. Otherwise a compromised
// rendezvous could attribute peer A's signed blob to peer B's
// NodeID and confuse lookups.
func TestVerify_TamperedNodeID(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 100, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	blob.NodeID = 200
	if err := blob.Verify(now, 0, nil); err == nil {
		t.Fatalf("Verify accepted tampered NodeID")
	}
}

// TestVerify_Expired: a blob whose ValidUntil is in the past
// must be rejected. Tested with a now that's 1ms past
// ValidUntil — the boundary case is the one most likely to
// regress under refactors.
func TestVerify_Expired(t *testing.T) {
	id := freshIdentity(t)
	signedAt := time.Date(2026, 4, 25, 19, 0, 0, 0, time.UTC)
	blob, err := Sign(id, 1, "1.2.3.4:5678", signedAt, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	expiredAt := time.UnixMilli(blob.ValidUntil + 1)
	if err := blob.Verify(expiredAt, 0, nil); err == nil {
		t.Fatalf("Verify accepted expired blob")
	}
}

// TestVerify_RejectsNonPositiveValidity: if for any reason
// ValidUntil <= IssuedAt, we must reject — this would be a
// signed blob that's instantly invalid, almost certainly the
// product of a malicious re-encoding rather than a legitimate
// peer.
func TestVerify_RejectsNonPositiveValidity(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 1, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Force ValidUntil = IssuedAt and re-sign so the bad-shape
	// signature is itself valid; the bounds check must still
	// reject.
	blob.ValidUntil = blob.IssuedAt
	payload := canonicalPayload(blob.NodeID, blob.PublicKey, blob.TURNEndpoint, blob.IssuedAt, blob.ValidUntil)
	blob.Signature = ed25519.Sign(id.PrivateKey, payload)
	if err := blob.Verify(now, 0, nil); err == nil {
		t.Fatalf("Verify accepted ValidUntil == IssuedAt")
	}
}

// TestVerify_RejectsValidityWindowTooLong: a blob claiming
// validity for longer than MaxValidityWindow must be rejected
// even if otherwise well-signed. Bounds the long-replay
// surface.
func TestVerify_RejectsValidityWindowTooLong(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	// Forge a blob with a 24h window and a valid sig over those
	// fields. Sign() caps at MaxValidityWindow internally, so
	// build the blob by hand here.
	issuedAt := now.UnixMilli()
	validUntil := issuedAt + (24 * time.Hour).Milliseconds()
	blob := &AnnounceBlob{
		NodeID:       1,
		PublicKey:    id.PublicKey,
		TURNEndpoint: "1.2.3.4:5678",
		IssuedAt:     issuedAt,
		ValidUntil:   validUntil,
	}
	blob.Signature = ed25519.Sign(id.PrivateKey,
		canonicalPayload(blob.NodeID, blob.PublicKey, blob.TURNEndpoint, blob.IssuedAt, blob.ValidUntil))
	if err := blob.Verify(now, 0, nil); err == nil {
		t.Fatalf("Verify accepted overly-long validity window")
	}
}

// TestVerify_ExpectedNodeIDMismatch: when the caller supplies
// expectedNodeID, a blob whose NodeID disagrees must be
// rejected even before signature math runs (cheap-fail).
func TestVerify_ExpectedNodeIDMismatch(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 100, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := blob.Verify(now, 200, nil); err == nil {
		t.Fatalf("Verify accepted blob with wrong NodeID under expected=200")
	}
	// Sanity: the same blob accepts its own NodeID.
	if err := blob.Verify(now, 100, nil); err != nil {
		t.Fatalf("Verify with correct expected NodeID: %v", err)
	}
}

// TestVerify_ExpectedPubkeyMismatch: similarly, when the caller
// provides a roster-bound expected public key, a blob signed
// by a different identity must be rejected.
func TestVerify_ExpectedPubkeyMismatch(t *testing.T) {
	id1 := freshIdentity(t)
	id2 := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id1, 1, "1.2.3.4:5678", now, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := blob.Verify(now, 0, id2.PublicKey); err == nil {
		t.Fatalf("Verify accepted blob signed by id1 under expected=id2")
	}
	if err := blob.Verify(now, 0, id1.PublicKey); err != nil {
		t.Fatalf("Verify with correct expected pubkey: %v", err)
	}
}

// TestVerifyPUT_RejectsClockSkew: the server-only PUT path must
// reject blobs whose IssuedAt is more than ClockSkewTolerance
// from the server's clock. Defends the bbolt store from
// pre-dated or future-dated injections.
func TestVerifyPUT_RejectsClockSkew(t *testing.T) {
	id := freshIdentity(t)
	signedAt := time.Date(2026, 4, 25, 19, 0, 0, 0, time.UTC)
	blob, err := Sign(id, 1, "1.2.3.4:5678", signedAt, 5*time.Minute)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// 6 minutes later — outside the 5-minute window.
	tooLate := signedAt.Add(ClockSkewTolerance + time.Minute)
	if err := blob.VerifyPUT(tooLate); err == nil {
		t.Fatalf("VerifyPUT accepted clock skew > ClockSkewTolerance")
	}
	// Within the window — accepted.
	withinWindow := signedAt.Add(ClockSkewTolerance - time.Second)
	if err := blob.VerifyPUT(withinWindow); err != nil {
		t.Fatalf("VerifyPUT in-window: %v", err)
	}
}

// TestSign_RejectsTooLongEndpoint: input validation on Sign so
// callers can't silently produce blobs that the server (or a
// peer) will refuse on Verify.
func TestSign_RejectsTooLongEndpoint(t *testing.T) {
	id := freshIdentity(t)
	tooLong := make([]byte, MaxTURNEndpointLen+1)
	for i := range tooLong {
		tooLong[i] = 'x'
	}
	_, err := Sign(id, 1, string(tooLong), time.Now(), 5*time.Minute)
	if err == nil {
		t.Fatalf("Sign accepted endpoint longer than MaxTURNEndpointLen")
	}
}

// TestSign_RejectsEmptyEndpoint: an empty endpoint is never
// useful and would cause confusing lookup failures downstream.
func TestSign_RejectsEmptyEndpoint(t *testing.T) {
	id := freshIdentity(t)
	_, err := Sign(id, 1, "", time.Now(), 5*time.Minute)
	if err == nil {
		t.Fatalf("Sign accepted empty endpoint")
	}
}

// TestSign_TTLCappedToMax: a caller asking for 24h of validity
// must silently get MaxValidityWindow instead — the cap is the
// system's authoritative upper bound.
func TestSign_TTLCappedToMax(t *testing.T) {
	id := freshIdentity(t)
	now := time.Now()
	blob, err := Sign(id, 1, "1.2.3.4:5678", now, 24*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	span := time.Duration(blob.ValidUntil-blob.IssuedAt) * time.Millisecond
	if span != MaxValidityWindow {
		t.Fatalf("validity span: got %s, want %s", span, MaxValidityWindow)
	}
}
