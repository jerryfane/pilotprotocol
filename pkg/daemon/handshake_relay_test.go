package daemon

import "testing"

const (
	testPublicKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testPublicKeyB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
)

func TestProcessRelayedRequestStoresProvidedPublicKey(t *testing.T) {
	d := New(Config{})
	const peerID uint32 = 45981
	const peerPublicKey = "pilot-public-key"
	d.handshakes.processRelayedRequest(peerID, peerPublicKey, "entmoot onboarding")
	defer d.handshakes.Stop()

	d.handshakes.mu.RLock()
	pending := d.handshakes.pending[peerID]
	d.handshakes.mu.RUnlock()
	if pending == nil {
		t.Fatal("relayed request was not stored as pending")
	}
	if pending.PublicKey != peerPublicKey {
		t.Fatalf("pending public key = %q, want %q", pending.PublicKey, peerPublicKey)
	}
}

func TestUpdateTrustedPeerPublicKeyBackfillsMissingKey(t *testing.T) {
	d := New(Config{})
	defer d.handshakes.Stop()
	const peerID uint32 = 155760
	d.handshakes.trusted[peerID] = &TrustRecord{NodeID: peerID}

	if !d.handshakes.updateTrustedPeerPublicKey(peerID, testPublicKeyA, "") {
		t.Fatal("updateTrustedPeerPublicKey did not report an update")
	}
	if got := d.handshakes.trusted[peerID].PublicKey; got != testPublicKeyA {
		t.Fatalf("trusted public key = %q, want %q", got, testPublicKeyA)
	}
}

func TestUpdateTrustedPeerPublicKeyRefreshesStaleKey(t *testing.T) {
	d := New(Config{})
	defer d.handshakes.Stop()
	const peerID uint32 = 133053
	d.handshakes.trusted[peerID] = &TrustRecord{NodeID: peerID, PublicKey: testPublicKeyA}

	if !d.handshakes.updateTrustedPeerPublicKey(peerID, testPublicKeyB, "") {
		t.Fatal("updateTrustedPeerPublicKey did not report an update")
	}
	if got := d.handshakes.trusted[peerID].PublicKey; got != testPublicKeyB {
		t.Fatalf("trusted public key = %q, want %q", got, testPublicKeyB)
	}
}

func TestUpdateTrustedPeerPublicKeyDoesNotCreateTrust(t *testing.T) {
	d := New(Config{})
	defer d.handshakes.Stop()
	const peerID uint32 = 45491

	if d.handshakes.updateTrustedPeerPublicKey(peerID, testPublicKeyA, "") {
		t.Fatal("updateTrustedPeerPublicKey updated a non-trusted peer")
	}
	if _, ok := d.handshakes.trusted[peerID]; ok {
		t.Fatal("updateTrustedPeerPublicKey created a trust record")
	}
}
