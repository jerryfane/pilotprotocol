package registry

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

func TestPollHandshakesIncludesRequesterPublicKey(t *testing.T) {
	s := New("")
	fromID := uint32(1)
	toID := uint32(2)
	fromIdentity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity from: %v", err)
	}
	toIdentity, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity to: %v", err)
	}
	s.nodes[fromID] = &NodeInfo{ID: fromID, PublicKey: fromIdentity.PublicKey}
	s.nodes[toID] = &NodeInfo{ID: toID, PublicKey: toIdentity.PublicKey}

	challenge := fmt.Sprintf("handshake:%d:%d", fromID, toID)
	_, err = s.handleRequestHandshake(map[string]interface{}{
		"from_node_id":  float64(fromID),
		"to_node_id":    float64(toID),
		"justification": "entmoot onboarding",
		"signature":     base64.StdEncoding.EncodeToString(fromIdentity.Sign([]byte(challenge))),
	})
	if err != nil {
		t.Fatalf("handleRequestHandshake: %v", err)
	}

	pollChallenge := fmt.Sprintf("poll_handshakes:%d", toID)
	resp, err := s.handlePollHandshakes(map[string]interface{}{
		"node_id":   float64(toID),
		"signature": base64.StdEncoding.EncodeToString(toIdentity.Sign([]byte(pollChallenge))),
	})
	if err != nil {
		t.Fatalf("handlePollHandshakes: %v", err)
	}
	requests, _ := resp["requests"].([]map[string]interface{})
	if len(requests) != 1 {
		t.Fatalf("requests len = %d, want 1: %#v", len(requests), resp["requests"])
	}
	got, _ := requests[0]["public_key"].(string)
	want := crypto.EncodePublicKey(fromIdentity.PublicKey)
	if got != want {
		t.Fatalf("public_key = %q, want %q", got, want)
	}
}
