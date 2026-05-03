package daemon

import "testing"

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
